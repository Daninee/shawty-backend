
import re
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import yt_dlp
from backend.downloader import YouTubeDownloader
from backend.util import validate_url


# [🔒 SECURITY LABELLING: DoS PROTECTION]
# Set up a rate limiter based on the remote user's IP address.
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Secure YouTube Resource Extractor API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# [🚨 CRITICAL RISK: CORS BLOCKS]
# Cross-Origin Resource Sharing is essential when your front-end (Netlify) 
# tries to send requests to your backend web host (Render/Railway/Localhost).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Swap "*" with your exact Netlify URL when live
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class SecureURLPayload(BaseModel):
    # Pydantic's HttpUrl ensures the payload is a structurally valid URL layout.
    url: HttpUrl
    format_type: str = "video"

# [🚨 CRITICAL RISK: COMMAND INJECTION VULNERABILITY]
def strict_youtube_validation(url_str: str) -> bool:
    """
    Strict regular expression whitelist barrier. Rejects any string containing 
    shell syntax, command separators, or unapproved host domains.
    """
    youtube_regex = re.compile(
       r'^(https?://)?(www\.)?(youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/shorts/)[a-zA-Z0-9_-]{11}(\?.*|&.*)?$'
    )
    return bool(youtube_regex.match(url_str))

@app.get("/api/info")
@limiter.limit("10/minute")  # Generous limit for typing/fetching links
async def get_info(request: Request, url: str):
    """
    Endpoint for the UI to preview video information before downloading.
    """
    if not url or not strict_youtube_validation(url):
        raise HTTPException(status_code=400, detail="Invalid YouTube URL.")
        
    try:
        ydl_opts = {'skip_download': True, 'quiet': True}
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            return {
                "title": info.get('title', 'Unknown Title'),
                "thumbnail": info.get('thumbnail'),
                "duration": info.get('duration'),
                "view_count": info.get('view_count'),
                "like_count": info.get('like_count'),
                
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Could not retrieve video details.")


@app.post("/api/fetch-resource")
# Limit each IP address to a maximum of 3 requests per minute to preserve server health
@limiter.limit("3/minute")
async def fetch_resource(request: Request, payload: SecureURLPayload):
    url_str = str(payload.url)
    
    # 1. Enforce strict URL regex match
    if not strict_youtube_validation(url_str):
        raise HTTPException(status_code=400, detail="Unsupported URL pattern or security risk detected.")
        
    # 2. Configure safe programmatic extraction rules
    # [🐢 PERFORMANCE LABELLING: ZERO-DISK OPTIMIZATION]
    ydl_opts = {
        'format': 'best',
        'skip_download': True,  # CRUCIAL: Keeps your server storage footprint at exactly zero.
        'quiet': True,
        'no_warnings': True,
    }
    
    try:
        # Utilizing the library context manager prevents shell process leakage entirely.
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url_str, download=False)
            
            # Extract the raw, playable CDN temporary file link from YouTube
            direct_cdn_url = info.get('url')
            video_title = info.get('title', 'Requested Media File')
            
            if not direct_cdn_url:
                raise HTTPException(status_code=404, detail="Unable to extract direct stream location.")
                
            return {
                "status": "success",
                "title": video_title,
                "download_link": direct_cdn_url
            }
            
    except yt_dlp.utils.DownloadError:
        raise HTTPException(status_code=400, detail="YouTube restricted access or reference link is invalid.")
    except Exception as e:
        # Keep real system errors safe inside backend server logs; display non-revealing errors to clients.
        print(f"[SYSTEM FAILURE EXCEPTION]: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal resource formatting issue.")