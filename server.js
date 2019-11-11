const dotenv = require("dotenv")
    , express = require("express")
    , app = express()
    , crypto = require("crypto")
    , cookie = require("cookie")
    , nonce = require("nonce")()
    , request = require("request-promise")
    , querystring = require("querystring")
    
dotenv.config();

const apiKey = process.env.SHOPIFY_API_KEY
    , apiSecret = process.env.SHOPIFY_API_SECRET
    , scopes = process.env.SHOPIFY_SCOPES
    , forwardingAddress = process.env.SHOPIFY_CALLBACK_URL 
    , PORT = process.env.PORT || 3003


// Serve up static assets (usually on heroku)
if (process.env.NODE_ENV === "production") {
    app.use(express.static("src/build"));
}
  
app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.get("/shopify", (req, res) => {
    const shop = req.query.shop;
    if (shop) {
        const state = nonce();
        const redirectUri = forwardingAddress + "/shopify/callback";
        const installUrl = "https://" + shop +
            "/admin/oauth/authorize?client_id=" + apiKey +
            "&scope=" + scopes +
            "&state=" + state +
            "&redirect_uri=" + redirectUri;

        res.cookie("state", state);
        res.redirect(installUrl);
    } else {
        return res.status(400).send("Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request");
    }
});

app.get("/shopify/callback", (req, res) => {
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send("Request origin cannot be verified");
    }

    if (shop && hmac && code) {
        // DONE: Validate request is from Shopify
        const map = Object.assign({}, req.query);
        delete map["signature"];
        delete map["hmac"];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, "utf-8");
        const generatedHash = Buffer.from(
            crypto
                .createHmac("sha256", apiSecret)
                .update(message)
                .digest("hex"),
            "utf-8"
        );
        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        } catch (e) {
            hashEquals = false;
        };

        if (!hashEquals) {
            return res.status(400).send("HMAC validation failed");
        }

        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl = "https://" + shop + "/admin/oauth/access_token";
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                console.log("accessToken", accessToken);
                // DONE: Use access token to make API call to "shop" endpoint
                const shopRequestUrl = "https://" + shop + "/admin/shop.json";
                const shopRequestHeaders = {
                    "Content-Type": "application/json",
                    "X-Shopify-Access-Token": accessToken,
                };

                request.get(shopRequestUrl, { headers: shopRequestHeaders })
                    .then((shopResponse) => {
                        res.status(200).end(shopResponse);
                    })
                    .catch((error) => {
                        res.status(error.statusCode).send(error.error.error_description);
                    });
            })
            .catch((error) => {
                res.status(error.statusCode).send(error.error.error_description);
            });

    } else {
        res.status(400).send("Required parameters missing");
    }
});

app.get("/check", function (req, res) {

    const shopRequestUrl = "https://" + process.env.SHOPIFY_NAME + "/admin/shop.json";
    const shopRequestHeaders = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": process.env.SHOPIFY_TOKEN,
    };

    request.get({uri: shopRequestUrl, headers: shopRequestHeaders })
        .then((shopResponse) => {
            res.json(JSON.parse(shopResponse));
        })
        .catch((error) => {
            console.log(error);
            res.status(500);
        });
});

app.get("/play", function (req, res) {

    const shopRequestUrl = "https://" + process.env.SHOPIFY_NAME + "/admin/customers.json";
    const shopRequestHeaders = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": process.env.SHOPIFY_TOKEN,
    };

    request.get(shopRequestUrl, { headers: shopRequestHeaders })
        .then((shopResponse) => {
            // res.status(200).end(shopResponse);
            res.json(JSON.parse(shopResponse));
        })
        .catch((error) => {
            console.log(error);
            res.status(500);
        });
});

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});
