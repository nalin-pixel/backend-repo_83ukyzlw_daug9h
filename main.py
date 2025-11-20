import os
import io
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
from gridfs import GridFS

app = FastAPI(title="Seal File Service API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class CreateLinkRequest(BaseModel):
    file_id: str
    expires_in_minutes: int = 60
    max_downloads: int = 1
    password: Optional[str] = None


class CreateLinkResponse(BaseModel):
    token: str
    expires_at: datetime
    url: str


# Ensure DB and GridFS are available
if db is None:
    # API still starts; endpoints that require DB will raise clean error
    pass
else:
    fs = GridFS(db)


@app.get("/")
async def root():
    return {"service": "Seal File Service", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        from database import db as _db
        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = _db.name if hasattr(_db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


def require_db():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available. Configure DATABASE_URL and DATABASE_NAME.")
    return db


# Encryption helpers (simple AES-256-GCM via cryptography would be ideal, but avoid new deps).
# For MVP we store raw in GridFS and rely on signed links for access control. Can extend to KMS later.


@app.post("/api/upload")
async def upload_file(request: Request, file: UploadFile = File(...), database=Depends(require_db)):
    try:
        content = await file.read()
        size = len(content)
        content_type = file.content_type

        fs_local = GridFS(database)
        grid_id = fs_local.put(content, filename=file.filename, contentType=content_type)

        file_doc = {
            "original_name": file.filename,
            "size": size,
            "content_type": content_type,
            "gridfs_id": str(grid_id),
            "owner": None,
            "deleted": False,
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        inserted_id = database["fileitem"].insert_one(file_doc).inserted_id

        # Log
        database["auditlog"].insert_one({
            "action": "upload",
            "file_id": str(inserted_id),
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "status": "success",
            "created_at": now_utc(),
        })

        return {"file_id": str(inserted_id), "name": file.filename, "size": size}
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/files")
async def list_files(database=Depends(require_db)):
    items = list(database["fileitem"].find({"deleted": False}).sort("created_at", -1))
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/api/links", response_model=CreateLinkResponse)
async def create_link(payload: CreateLinkRequest, request: Request, database=Depends(require_db)):
    # Validate file exists
    file_doc = database["fileitem"].find_one({"_id": ObjectId(payload.file_id), "deleted": False})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    expires_at = now_utc() + timedelta(minutes=payload.expires_in_minutes)
    password_sha = hashlib.sha256(payload.password.encode()).hexdigest() if payload.password else None

    link_doc = {
        "file_id": payload.file_id,
        "token": token,
        "expires_at": expires_at,
        "max_downloads": payload.max_downloads,
        "downloads": 0,
        "password_sha256": password_sha,
        "revoked": False,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }

    database["link"].insert_one(link_doc)

    base_url = os.getenv("PUBLIC_BASE_URL") or ""
    url = f"{base_url}/api/d/{token}" if base_url else f"/api/d/{token}"

    # Log
    database["auditlog"].insert_one({
        "action": "create_link",
        "file_id": payload.file_id,
        "link_token": token,
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "status": "success",
        "created_at": now_utc(),
    })

    return CreateLinkResponse(token=token, expires_at=expires_at, url=url)


@app.post("/api/links/{token}/revoke")
async def revoke_link(token: str, request: Request, database=Depends(require_db)):
    res = database["link"].find_one_and_update(
        {"token": token},
        {"$set": {"revoked": True, "updated_at": now_utc()}},
        return_document=ReturnDocument.AFTER,
    )
    if not res:
        raise HTTPException(status_code=404, detail="Link not found")

    database["auditlog"].insert_one({
        "action": "revoke_link",
        "link_token": token,
        "status": "success",
        "created_at": now_utc(),
    })

    return {"revoked": True}


@app.get("/api/links")
async def list_links(database=Depends(require_db)):
    links = list(database["link"].find({}).sort("created_at", -1))
    for l in links:
        l["_id"] = str(l["_id"])
    return links


@app.get("/api/d/{token}")
async def download_by_token(token: str, request: Request, password: Optional[str] = None, database=Depends(require_db)):
    link = database["link"].find_one({"token": token})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    if link.get("revoked"):
        raise HTTPException(status_code=410, detail="Link revoked")

    if now_utc() > link["expires_at"]:
        raise HTTPException(status_code=410, detail="Link expired")

    if link.get("password_sha256"):
        supplied = hashlib.sha256((password or "").encode()).hexdigest()
        if supplied != link["password_sha256"]:
            raise HTTPException(status_code=401, detail="Invalid password")

    if link["downloads"] >= link["max_downloads"]:
        raise HTTPException(status_code=410, detail="Download limit reached")

    file_doc = database["fileitem"].find_one({"_id": ObjectId(link["file_id"])})
    if not file_doc or file_doc.get("deleted"):
        raise HTTPException(status_code=404, detail="File not available")

    fs_local = GridFS(database)
    try:
        grid_file = fs_local.get(ObjectId(file_doc["gridfs_id"]))
    except Exception:
        raise HTTPException(status_code=500, detail="File content missing")

    # Update download count
    database["link"].update_one({"_id": link["_id"]}, {"$inc": {"downloads": 1}, "$set": {"updated_at": now_utc()}})

    # Log
    database["auditlog"].insert_one({
        "action": "download",
        "file_id": str(file_doc["_id"]),
        "link_token": token,
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "status": "success",
        "created_at": now_utc(),
    })

    def iterfile():
        while True:
            chunk = grid_file.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    headers = {"Content-Disposition": f"attachment; filename=\"{file_doc['original_name']}\""}
    return StreamingResponse(iterfile(), media_type=file_doc.get("content_type") or "application/octet-stream", headers=headers)


@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str, request: Request, database=Depends(require_db)):
    file_doc = database["fileitem"].find_one({"_id": ObjectId(file_id)})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    database["fileitem"].update_one({"_id": file_doc["_id"]}, {"$set": {"deleted": True, "updated_at": now_utc()}})

    database["auditlog"].insert_one({
        "action": "delete",
        "file_id": file_id,
        "status": "success",
        "created_at": now_utc(),
    })

    return {"deleted": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
