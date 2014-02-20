var fs = require('fs')
var tls = require('tls')

var options = {
    port: 8386,
    ca: fs.readFileSync('t/certs/ca-cert.pem')
}

var client = tls.connect(options)

client.on('data', function (chunk) {
    console.log(chunk.toJSON())
    write()
})

function write () {
    client.write(new Buffer([ 1, 2, 3, 4 ]))
}

write()
