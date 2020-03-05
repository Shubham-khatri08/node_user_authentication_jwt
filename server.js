require('dotenv').config();

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

app.use(express.json());



// Database Connection 
var connection = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : 'python',
    database : 'node_task'
});
connection.connect(function(err){
    if(!err) {
        console.log("Database is connected ... nn");
    } else {
        console.log(err);
    }
});

// user registration
app.post('/register', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt)
        var today = new Date();
        var users={
            "name":req.body.name,
            "email":req.body.email,
            "password":hashedPassword,
            "created":today,
            "modified":today
        }
        connection.query('INSERT INTO users SET ?',users, function (error, results, fields) {
            if (error) {
              console.log("error ocurred",error);
              res.send({
                "code":400,
                "failed":"error ocurred"
              })
            }else{
              console.log('The solution is: ', results);
              res.send({
                "code":200,
                "success":"user registered sucessfully"
                  });
            }
        });

    } catch {
        res.status(500).send();
    }
})

let refresh_tokens = [];

// user login
app.post('/login', async (req, res) => {
    var email= req.body.email;
    var password = req.body.password;
    const user = { email : email };
    connection.query('SELECT * FROM users WHERE email = ?',[email], function (error, results, fields) {
        if (error) {
            return res.status(400).send("Cannot find user");
        }
        if(results.length >0){
            bcrypt.compare(password, results[0].password, function(err, ress){
                if(!ress){
                    res.json({
                      status:false,                  
                      message:"Email and password does not match"
                    });
                }else{                    
                    const access_token = generateAccessToken(user);
                    const refresh_token = jwt.sign(user, process.env.REFRESH_TOKEN);
                    refresh_tokens.push(refresh_token);
                    res.json({
                        access_token: access_token,
                        refresh_token: refresh_token
                    })
                }
            })
        } else {
            res.json({
                status:false,
                message:"Email does not exits"
            });
        }
    });
});

// Generate access token, which expire in 30 seconds
function generateAccessToken(user){
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '30s' })
}

// Re-Generate access token using refresh token 
app.post('/token', (req, res) => {
    const refresh_token = req.body.token;
    if (refresh_token == null ) return res.sendStatus(401)
    if (!refresh_tokens.includes(refresh_token)) return res.sendStatus(403)
    jwt.verify(refresh_token, process.env.REFRESH_TOKEN, (err, user) => {
        if (err) return res.sendStatus(403)
        const access_token = generateAccessToken({ name: user.name });
        res.json(
            {
                access_token: access_token
            }
        )
    })
})

// Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}


// User list 
app.get('/orders', authenticateToken, (req, res) => {
    var email = req.user.email;
    connection.query('select id, order_date from orders where user_id in (select id from users where email = ?)',[email], function (error, result, fileds){
        if (error) {
            return res.status(400).send("There is some error in query");
        }
        if (result.length > 0){
            res.json(result)
        }
        else {
            res.json({
                status:false,
                message:"Order does not exits"
            });
        }
    })
})

//User Name updation 
app.put('/user_update', authenticateToken, (req, res) => {
    var name = req.body.name;
    var email = req.user.email;
    var today = new Date();
    connection.query('update users set name = ?, modified = ? where email = ?',[name,today,email], function (error, result, fileds){
        if (error) {
            return res.status(400).send("There is some error in query");
        }
        else {
            res.send({
                "code":200,
                "success":"user updated sucessfully"
            });
        }
    })
})

app.listen(8000);