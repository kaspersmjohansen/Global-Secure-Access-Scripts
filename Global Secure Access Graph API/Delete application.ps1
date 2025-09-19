# Prepare body for API access token retrieval
$clientID = ""
$ClientSecret = ""
$body = @{
    client_id = $clientID
    client_secret = $ClientSecret
    scope = "https://graph.microsoft.com/.default"
    grant_type = "client_credentials"
}

# Get API access token
$tenantID = ""
$TokenEndpoint = "https://login.microsoft.com/$tenantId/oauth2/v2.0/token"
$tokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
$AccessToken = $tokenResponse.access_token
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# Get application Id
$ApplicationName = ""
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/applications/?`$Filter=displayname eq '$ApplicationName'"
    Headers = $Headers
}
$App = Invoke-RestMethod @params
$AppId = $App.value.id

# Delete application 
$params = @{
    Method = 'Delete'
    Uri = "https://graph.microsoft.com/beta/applications/$AppId"
    Headers = $Headers
}
Invoke-RestMethod @params