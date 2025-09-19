# Delete connector group

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

# Connector group name
$ConnectorGroupName = ""

$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/?`$Filter=name eq '$ConnectorGroupName'"
    Headers = $Headers
}
$ConnectorGroup = Invoke-RestMethod @params
$ConnectorGroupId = $ConnectorGroup.value.id

# Get default connector group Id
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/?`$Filter=name eq 'Default'"
    Headers = $Headers
}
$DefaultConnectorGroup = Invoke-RestMethod @params
$DefaultConnectorGroupId = $DefaultConnectorGroup.value.id

# List applications in connector group
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId/applications?select=id"
    Headers = $Headers
}
$ConnectorGroupApps = Invoke-RestMethod @params
$ConnectorGroupAppsId = $ConnectorGroupApps.value.id

# Get current connector members and get their Id
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId/members?select=id"
    Headers = $Headers
}
$ConnectorGroupMembers = Invoke-RestMethod @params
$ConnectorGroupMembersId = $ConnectorGroupMembers.value.id

# Delete application segments in applications
ForEach ($AppId in $ConnectorGroupAppsId)
{
    # Get applications segments
    $params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/applications/$AppId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.IpSegmentConfiguration/ApplicationSegments"
    Headers = $Headers
    }
        $AppSegment = Invoke-RestMethod @params
        $AppSegmentId = $AppSegment.value.id

            If ($AppSegmentId -gt '0')
            {
                # Delete application segment
                $params = @{
                Method = 'Delete'
                Uri = "https://graph.microsoft.com/beta/applications/$AppId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.IpSegmentConfiguration/ApplicationSegments/$AppSegmentId"
                Headers = $Headers
                }
                Invoke-RestMethod @params
            }
                    # Delete application 
                    $params = @{
                    Method = 'Delete'
                    Uri = "https://graph.microsoft.com/beta/applications/$AppId"
                    Headers = $Headers
                    }
                    Invoke-RestMethod @params
}

# Move existing connectors to the default connector group
ForEach ($ConnectorId in $ConnectorGroupMembersId)
{
    $Body = @{
    "@odata.id" = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectors/$ConnectorId"    
    } | ConvertTo-Json -Depth 99 -Compress

        $params = @{
            Method = 'Post'
            Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$DefaultConnectorGroupId/members/`$ref"
            Headers = $Headers
            Body = $Body
        }
        Invoke-RestMethod @params
}

# Delete connector group #
$params = @{
    Method = 'Delete'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId"
    Headers = $Headers
}
Invoke-RestMethod @params