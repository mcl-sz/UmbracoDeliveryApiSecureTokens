import './App.css';
import {
    AuthorizationNotifier,
    AuthorizationRequest,
    AuthorizationServiceConfiguration,
    BaseTokenRequestHandler,
    BasicQueryStringUtils,
    DefaultCrypto,
    FetchRequestor,
    GRANT_TYPE_AUTHORIZATION_CODE,
    LocalStorageBackend,
    RedirectRequestHandler,
    RevokeTokenRequest,
    TokenRequest
} from '@openid/appauth';
import {useState} from "react";

export class NoHashQueryStringUtils extends BasicQueryStringUtils {
    parse(input, useHash) {
        return super.parse(input, false /* never use hash */);
    }
}

// this is a quick and dirty monkey patch of fetch to forcefully include credentials (HTTP-only cookies),
// because it doesn't seem like appauth can include credentials in token requests.
const { fetch: originalFetch } = window;
window.fetch = async (...args) => {
    const [resource, config ] = args;
    // since the client performs cross-origin requests,
    // the credentials option must be 'include'
    config.credentials = 'include';
    try {
        return await originalFetch(resource, config);
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
};

function App() {
    const [accessToken, setAccessToken] = useState(undefined)
    const [contentItems, setContentItems] = useState(undefined)
    const [userInfo, setUserInfo] = useState(undefined)

    const serverUrl = "https://localhost:44393";
    const clientId = 'umbraco-member';
    const redirectUri = 'http://localhost:3000/';
    const scope = 'openid';

    const notifier = new AuthorizationNotifier();
    const authorizationHandler = new RedirectRequestHandler(new LocalStorageBackend(), new NoHashQueryStringUtils(), window.location, new DefaultCrypto());
    const tokenHandler = new BaseTokenRequestHandler(new FetchRequestor());

    let configuration = undefined;
    
	// setup notifier to listen for authorization completions
    authorizationHandler.setAuthorizationNotifier(notifier);
    notifier.setAuthorizationListener((request, response, error) => {
		// use PKCE
        let extras = undefined;
        if (request && request.internal) {
            extras = {};
            extras['code_verifier'] = request.internal['code_verifier'];
        }

		// create request for the token endpoint
        let tokenRequest = new TokenRequest({
            client_id: clientId,
            redirect_uri: redirectUri,
            grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
            code: response.code,
            refresh_token: undefined,
            extras: extras
        });

		// request an access token from the server
        return tokenHandler.performTokenRequest(configuration, tokenRequest).then(response => {
            setAccessToken(response.accessToken);
            return response;
        });
    });
    
    const startLoginFlow = () => {
        setContentItems(undefined);

		// create request for the authorization endpoint
        let request = new AuthorizationRequest({
            client_id: clientId,
            redirect_uri: redirectUri,
            scope: scope,
            response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
			// use this if you want to use a specific identity provider (e.g. external identity providers)
            extras: {
                // 'identity_provider': 'UmbracoMembers.GitHub'
            }
        });

		// initiate the authorization flow - this will eventually redirect the browser to the server for authorization
        authorizationHandler.performAuthorizationRequest(configuration, request);
    }

    const startLogoutFlow = () => {
        setContentItems(undefined);

		// create request for the revocation endpoint
        let request = new RevokeTokenRequest({
            token: accessToken,
            client_id: clientId
        })

		// initiate the revocation flow - this will invalidate the supplied access token
        tokenHandler.performRevokeTokenRequest(configuration, request).then(response => {
            if(response) {
                setAccessToken(undefined);
				// the token was revoked - now redirect the browser to the "end session" endpoint to
				// terminate the member session on the server
                window.location = `${configuration.endSessionEndpoint}?post_logout_redirect_uri=${redirectUri}`
            }
        })
    }

	// auto-detect the server configuration from its ".well-known" configuration (/.well-known/openid-configuration)
    AuthorizationServiceConfiguration.fetchFromIssuer(serverUrl, new FetchRequestor())
        .then(response => {
            configuration = response;

			// initiate completion of the authorization flow if this is a callback from the server
            authorizationHandler.completeAuthorizationRequestIfPossible().then(() => {
                // (add any handling for successful authorization here)
				if (accessToken && !userInfo) {
				   fetchUser();
				}



            });
        });
	
    const fetchRootItems = () => {
        setContentItems(undefined);

		// fetch all articles of the content root ("home") using bearer token auth with the obtained access token (if any)
        fetch(
            `${serverUrl}/umbraco/delivery/api/v2/content/?fetch=children:/&filter=contentType:article`,
            {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Start-Item': 'home'
                }
            }
        )
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            setContentItems(data);
        });
    };


    const fetchUser = () => {
        setUserInfo(undefined);

		// fetch all articles of the content root ("home") using bearer token auth with the obtained access token (if any)
        fetch(
            `${serverUrl}/umbraco/delivery/api/v1/security/member/userinfo`,
            {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`
                }
            }
        )
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            setUserInfo(data);
        });
    };
    
    return (
        <div className="App">
            { accessToken && <>
                    <h1>Whoo {userInfo && userInfo.name}! You're authorized 😃</h1>
                    <button type="button" className="btn btn-primary" onClick={startLogoutFlow}>Yikes! Log me out!</button>
                    <p>Your access token is: <strong>{accessToken}</strong></p>
					<p><s>If you fancy, you can use the token as a bearer token to test the Delivery API with your favorite API testing tool.</s></p>
                    <p>👆 Hopefully not 😉</p>
                </>
            }
            { !accessToken && <>
                    <h1>Uh, ouh. You're not authorized 😔</h1>
                    <p>How about we hit the button below to fix that?</p>
                    <button type="button" className="btn btn-primary" onClick={startLoginFlow}>Go, go, login!</button>
                </>
            }
			<p>Read all about member authorization in the Delivery API in <a href="https://docs.umbraco.com/umbraco-cms/reference/content-delivery-api/protected-content-in-the-delivery-api" title="Member authorization documentation" target="_blank" rel="noreferrer">the Umbraco documentation</a></p>
            <h2>Go grab yourself some content 👇</h2>
			<p>Hit the button to fetch the content you're allowed to see.</p>
            <button type="button" className="btn btn-secondary" onClick={fetchRootItems}>Go fetch 🐶</button>
            { contentItems && <>
					<h2>Got <strong>{ contentItems.total }</strong> content items 📄</h2>
					<ul>
						{ contentItems.items.map(item => (<li>{item.name}</li>)) }
					</ul>
                </>
            }
			
        </div>
    );
}

export default App;
