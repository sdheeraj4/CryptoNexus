from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.errors import register_error_handlers
from app.logging_config import configure_logging
from app.uploads import ScanResult, MAX_UPLOAD_BYTES, process_upload

configure_logging()
app = FastAPI(title="CryptoNexus", version="0.1.0")
register_error_handlers(app)


class RequestSizeLimit:
    """Bound the multipart body before FastAPI spools uploaded files to disk."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = MAX_UPLOAD_BYTES + 1024 * 1024  # Allow multipart framing.
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"error": "Invalid Content-Length."}, 400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"error": "Request exceeds the 21 MiB limit."}, 413)(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > limit:
                raise HTTPException(413, "Request exceeds the 21 MiB limit.")
            return message

        await self.app(scope, limited_receive, send)


app.add_middleware(RequestSizeLimit)


@app.get("/health")
def health():
    return {"status": "ok", "service": "CryptoNexus"}


@app.post("/api/upload", response_model=ScanResult)
def upload_repository(file: UploadFile = File(...)):
    return process_upload(file)
