import json
import secrets
from fastapi import Request, HTTPException, APIRouter
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

router = APIRouter()

CLIENT_ID = 'XXXX'  #paste your client id from hubspot
CLIENT_SECRET = 'XXXX' # Replace with your actual Client Secret
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

# Update the scopes as needed
scopes = 'crm.objects.contacts.read crm.objects.contacts.write'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={scopes}'

encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

@router.post('/authorize_hubspot')
async def authorize_hubspot(user_id: str, org_id: str):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = json.dumps(state_data)
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600)

    return {"authorization_url": f'{authorization_url}&state={encoded_state}'}

@router.get('/oauth2callback_hubspot')
async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(encoded_state)

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

@router.post('/credentials')
async def get_hubspot_credentials(user_id: str, org_id: str):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

def create_integration_item_metadata_object(response_json: str, item_type: str, parent_id=None, parent_name=None) -> IntegrationItem:
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('name', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )

    return integration_item_metadata

async def fetch_items(access_token: str, url: str, aggregated_response: list, after=None):
    params = {'after': after} if after else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)

    if response.status_code == 200:
        results = response.json().get('results', [])
        after = response.json().get('paging', {}).get('next', {}).get('after', None)

        aggregated_response.extend(results)

        if after:
            await fetch_items(access_token, url, aggregated_response, after)

