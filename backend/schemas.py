"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Class name lowercased = collection name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

# Auth/account schema for users of the Brew Haven site
class Account(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = Field(None, description="Optional avatar image URL")
    is_active: bool = Field(True, description="Whether the account is active")

# Example product schema for potential future use
class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category: str
    in_stock: bool = True
