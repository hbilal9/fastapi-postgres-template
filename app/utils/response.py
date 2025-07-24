from typing import Any, Dict, Optional, Union
from pydantic import BaseModel
from fastapi.responses import JSONResponse


class StandardResponse(BaseModel):
    data: Optional[Any] = None
    is_success: bool = True
    error: Optional[Dict[str, Any]] = None
    meta_data: Optional[Dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True


def success_response(
    data: Any = None, 
    meta_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    return {
        "data": data,
        "is_success": True,
        "error": None,
        "meta_data": meta_data
    }


def error_response(
    error_message: str,
    error_details: Optional[Dict[str, Any]] = None,
    meta_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    error_data = {"message": error_message}
    if error_details:
        error_data.update(error_details)
    
    return {
        "data": None,
        "is_success": False,
        "error": error_data,
        "meta_data": meta_data
    }