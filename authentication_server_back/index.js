const express = require('express');
const fileUpload = require('express-fileupload');
var multer = require('multer')
const cors = require('cors');
var fs = require('fs');

const { exec } = require("child_process");

const app = express();

app.use(cors())

app.use(fileUpload()); // Don't forget this line!

app.post("/api/register", function(req, res)
{
    if (!req.files) {
        return res.status(500).send({ msg: "file is not found" })
    }

    // accessing the file
    const myFile = req.files.file;    //  mv() method places the file inside public directory

    myFile.mv(`${__dirname}/keys/${myFile.name}`, function (err) {
        if (err) {
            console.log(err)
            return res.status(500).send({ msg: "Error occured" });
        }
        // returing the response with file path and name
        //return res.send({name: myFile.name, path: `/${myFile.name}`});
    });

    exec(`openssl x509 -req -in ${__dirname}/keys/${myFile.name} -CA ${__dirname}/keys/ca.crt -CAkey ${__dirname}/keys/ca.key -CAcreateserial -out ${__dirname}/keys/user.crt`, (error, stdout, stderr) => {

        if (error) {
            console.log(`error: ${error.message}`);
            return;
        }
        else if (stderr) {
            fs.unlink(`${__dirname}/keys/${myFile.name}`, (err) => {
                if (err) {
                    console.error(err)
                }
                else{
                    console.log("File removed");
                    const file = `${__dirname}/keys/user.crt`;
                    res.download(file); // Set disposition and send it.
                    fs.unlink(`${__dirname}/keys/user.crt`, (err) => {
                        if(err) {
                            console.log("ERROR");
                        }
                        else{
                            console.log("SUCCESS");
                        }
                    });

                }            
            });
        }
});




});

var server = app.listen(8081, function () {
   var host = server.address().address
   var port = server.address().port
   console.log("listening at http://%s:%s", host, port)
})