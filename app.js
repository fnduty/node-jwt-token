// var Base64 = require('js-base64').Base64;
// const uuid = require('node-uuid')
var generateRSAKeypair = require('generate-rsa-keypair')
var jwt = require('jsonwebtoken');
const path = require('path')
const fs = require('fs')
const morgan = require('morgan')
const express = require('express')
var bodyParser = require('body-parser');
const app = express()
const port = 3000



app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded






app.post('/api/v1/oauth/token', async (req, res) => {
    try {
        const { grant_type } = req.body

        switch (grant_type) {
            case 'password':
                const { token, expiresIn  } = await passwordAuth(req)
                return res.status(200).json({
                    token_type: "bearer",
                    access_token: token,
                    expires_in: expiresIn,
                    refresh_token: '',
                });

            case 'refresh_token':
                
                const isValid = await refreshToken(req)

                console.log( 'isValid', isValid );

                if (!isValid) {
                    res.status(401).json({
                        status: "401",
                        error: 'Unauthorized',
                        message: "Must provide a valid refresh token"
                    }) 
                }
                
                return res.status(200).json({
                    token_type: "bearer",
                    access_token: '',
                    expires_in: '',
                    refresh_token: '',
                });
        }
        
        throw new Error('Bad request')

    } catch (error) {
        console.log( 'error catched', error );
        
        res.status(400).json({
            status: "error",
            error: 'Bad Request'
        })  
    }
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))




function passwordAuth (req) {
    try {
    const {email, password} = req.body

    var pair = generateRSAKeypair()
    var cert = fs.writeFileSync('./public.pem', pair.public);  // get public key
            
    return new Promise((resolve, reject) => {
            // var expiresIn = 60 * 60
            var expiresIn = 60
            jwt.sign({ 
                foo: 'bar',
                // iat: Math.floor(Date.now() / 1000) - 30,  // issue_at
                // exp: Math.floor(Date.now() / 1000) + (60 * 60),  // expiration
            }, pair.private, { 
                algorithm: 'RS256',
                expiresIn
            }, function(err, token) {
                if (err) reject(err)
                resolve({
                    token,
                    expiresIn
                })
            })
        })
        .then((token) => {
            return token  
        })
    } catch (error) {
        reject(error)
    }
}


function refreshToken (req) {
    try {
        const { refresh_token } = req.body        
        return new Promise((resolve, reject) => {
            var cert = fs.readFileSync('./public.pem');  // get public key   
            jwt.verify(refresh_token, cert, function(err, decoded) {
                if (err) resolve(false)
                if (decoded === undefined) resolve(false)
                resolve(decoded)
            });            
        })
    } catch (error) {
        reject(error)
    }
}