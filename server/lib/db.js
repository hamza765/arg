import pg from 'pg';
pg.defaults.poolSize = 25;
const conString = "postgresql://postgres:goTime2016!@ssl-scanner.covftl8i0gnh.us-east-1.rds.amazonaws.com/ssl_scanner" //U:Scanner P: Pavilion6!
    //const conString = "postgres://postgres:password@localhost/ssl_scanner"; 

export default function(q, callback) {
    pg.connect(conString, function(err, client, done) {
        if (err) {
            console.log(err);
            callback(err);
        } else {
            client.query(q, function(err, result) {
                done();
                callback(err, result);
            });
        }
    });
}
