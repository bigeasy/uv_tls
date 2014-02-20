var tls = require('tls')
var fs = require('fs')

var options = {
    key: fs.readFileSync('t/certs/agent-key.pem'),
    cert: fs.readFileSync('t/certs/agent-cert.pem')
}

var server = tls.createServer(options, function(stream) {
     console.log('connect');
    stream.on('data', function (chunk) {
        console.log({ length: chunk.length })
        setTimeout(function () {
            console.log('sending')
            stream.write(chunk)
        }, 1000)
    })
    stream.on('end', function() {
        console.log('server disconnected')
    })
})
server.listen(8386, function() {
    console.log('server bound')
})
