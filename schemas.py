"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# Example schemas (kept for reference):

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product" (lowercase of class name)
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Secure File Service Schemas

class FileItem(BaseModel):
    """
    Stored files metadata
    Collection name: "fileitem" -> "fileitem" collection
    """
    original_name: str = Field(..., description="Original filename from uploader")
    size: int = Field(..., ge=0, description="File size in bytes")
    content_type: Optional[str] = Field(None, description="MIME type")
    gridfs_id: Optional[str] = Field(None, description="GridFS ObjectId (as string)")
    owner: Optional[str] = Field(None, description="Uploader identifier (optional)")
    deleted: bool = Field(False, description="Soft delete flag")

class Link(BaseModel):
    """
    Download links for files
    Collection name: "link"
    """
    file_id: str = Field(..., description="FileItem document id (as string)")
    token: str = Field(..., description="Random unique token for public download")
    expires_at: datetime = Field(..., description="Link expiry timestamp (UTC)")
    max_downloads: int = Field(1, ge=1, description="Maximum allowed downloads")
    downloads: int = Field(0, ge=0, description="Current download count")
    password_sha256: Optional[str] = Field(None, description="SHA256 hash of optional password")
    revoked: bool = Field(False, description="Whether the link has been revoked")

class AuditLog(BaseModel):
    """
    Audit logs for actions
    Collection name: "auditlog"
    """
    action: str = Field(..., description="Action name, e.g., upload, download, revoke")
    file_id: Optional[str] = Field(None)
    link_token: Optional[str] = Field(None)
    ip: Optional[str] = Field(None)
    user_agent: Optional[str] = Field(None)
    status: str = Field(..., description="success|error with details")
    message: Optional[str] = Field(None)

# Note: The Flames database viewer will automatically:
# 1. Read these schemas from GET /schema endpoint
# 2. Use them for document validation when creating/editing
# 3. Handle all database operations (CRUD) directly
# 4. You don't need to create any database endpoints!
