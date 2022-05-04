//express 불러오기
const { response } = require("express");
const express = require("express");
const { request } = require("http");
const bodyParser = require('body-parser');
const https = require("https");
const fs = require("fs");
// const node_openssl = require("node-openssl-cert");
const node_openssl = require("./node-openssl-cert-master");
const spawn = require("child_process").spawn;

const ocsp = require("ocsp");

const { X509Certificate } = require('crypto');

//ssl 자체 인증(서명) 서버를 만들기 위해서는 key와 csr이 필요
const options = {
	ca : fs.readFileSync('./rootca.crt'),
	key : fs.readFileSync('./corgi.key'),
	cert : fs.readFileSync('./corgi.crt'),
	passphrase : 'elwlxjfwhs1!'
};

var cacrt = fs.readFileSync('./rootca.crt');
var cakey = fs.readFileSync('./rootca.key');
var cacsr = fs.readFileSync('./rootca.csr');

var ssloptions = {
	binpath: 'C:/Users/admin/Desktop/OpenSSL/bin/openssl.exe'
}

const openssl = new node_openssl(ssloptions);

//express 사용
//const app = express();
const app = express();

//포트 번호 설정
const port = 5000;

https.createServer(options, app, (request,response)=> {
	console.log("createServer");
}).listen(port, () => {
	console.log("server start on 5000");
});

//http 서버 실행
// app.listen(port,() => {
//     console.log("server start on 5000");
// })

// node.js 모듈(body-parser)
// 클라이언트 POST request data의 body로부터 파라미터를 편리하게 추출
app.use(bodyParser.json());

/*
	false면 기본으로 내장된 querystring 모듈을 사용하고
	true면 따로 설치가 필요한 qs 모듈을 사용하여 쿼리 스트링을 해석
	기존 querystring 모듈과 qs 모듈의 차이는 중첩 객체 처리라고 보면 됨
*/
app.use(express.urlencoded({extended: false}));



// http:/localhost:5000/ 경로로 접근시
app.all("/", async (request,response) => {

	var rsakeyoptions = {
		encryption: {
			password: 'elwlxjfwhs1!',
			cipher: 'des3'
		},
		rsa_keygen_bits: 2048,
		rsa_keygen_pubexp: 65537,
		format: 'PKCS8'
	};

	var csroptions = {
		hash: 'sha1',
		days: "7",
		subject: { // req_distinguished_name
			countryName: 'KR',
			organizationName : 'corgicorgicorgicorgi',
			emailAddress: 'kec@digitalzone.co.kr'
		},
		extensions: {
			basicConstraints: {
				critical: true,
				CA: true,
				pathlen: 1
			},
			keyUsage: {
				//critical: false,
				usages: [
					'digitalSignature',
					'keyEncipherment'
				]
			},
			extendedKeyUsage: {
				critical: true,
				usages: [
					'serverAuth',
					'clientAuth'
				]	
			},
			SANs: {
				DNS: [
					'www.welshcorgi.com'
				]
			}
		}
	}
	
	var kimoption = {
		days: "7",
		extensions: "v3_user"
	}



	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		console.log("cmd : ");
		console.log(cmd);
		console.log("key : ");
		console.log(key);
		openssl.generateCSR(csroptions, key, 'elwlxjfwhs1!', function(err, csr, cmd) {
			if(err) {
				console.log(err);
			} else {
				console.log("cmd.command : ");
				console.log(cmd.command);
				console.log("csr : ");
				console.log(csr);
				console.log("cmd.files.config : ");
				console.log(cmd.files.config);
			}

			
			//extensions: "v3_user", in: cacsr.toString('utf-8'), CA: cacrt.toString('utf-8')
			// 'C:/Users/admin/Desktop/OpenSSL/bin/test2/rootca.crt', 'C:/Users/admin/Desktop/OpenSSL/bin/test2//rootca.key'
			openssl.CASignCSR(csr, csroptions,false, cacrt, cakey , 'elwlxjfwhs1!', function(err, crt, cmd) {
				if(err) console.log(err);
				console.log("--------------------------------");
				
				openssl.getCertInfo(cacrt, function(err, attrs, cmd) {
					if(err) {
						console.log(err);
					} else {
						console.log(attrs);
					}
				});
				// fs.writeFile('./test.crt',crt,function(err){
				// 	if (err === null) {
				// 		console.log('success'); 
				// 	} else { 
				// 		console.log('fail');
				// 	}
				// });
			});
		});
	});

	var pri_key = fs.readFileSync('./rootca.key', 'utf-8');
	var pub_key = fs.readFileSync('./rootca_pubkey.pem', 'utf-8');


	const res = {
		pri_key: pri_key,
		pub_key : pub_key,
		error: null
	}
		
	response.send(res);
});


// http:/localhost:5000/ 경로로 접근시
app.all("/catest", async (request,response) => {

	

	var rsakeyoptions = {
		encryption: {
			password: 'elwlxjfwhs1!',
			cipher: 'des3'
		},
		rsa_keygen_bits: 2048,
		rsa_keygen_pubexp: 65537,
		format: 'PKCS8'
	};


	openssl.generateRSAPrivateKey(rsakeyoptions, (err, key, cmd) => {
		console.log("cmd : ");
		console.log(cmd);
		console.log("key : ");
		console.log(key);

	});


	// let keyArgs = ['genrsa','-des3', '-out', './testtest.pem', '2048'];
	// let keyArgs = ['genrsa','-aes128', '-passout pass:elwlxjfwhs1!', '-out', './testtest.pem', '2048'];
	// let keyArgs = ['genrsa -des3 -passout pass:elwlxjfwhs1! -out ./testtest.pem 2048'];
	// let keyArgs = ['genpkey -outform PEM -algorithm RSA -pass '  'elwlxjfwhs1!' , '-des3 -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out priv.key']
	// let keyArgs = ['genpkey -aes-256-cbc -pass pass:elwlxjfwhs1! -algorithm RSA -out ./testtest.pem -pkeyopt rsa_keygen_bits:2048'];
	
	// spawn('openssl', keyArgs, {stdio: 'pipe'}).on('exit', (code) => {
	// 	console.log(code);
	// 	console.log("asdf");
    // 	if (code !== 0) {
	// 		console.log("asdf");
    // 		process.umask(oldmask);
    // 		return reject(new Error("error generating key: return code " + code));
    // 	}
	// });

	// let csrArgs = ['req', '-config', './openssl.cnf',
    // '-subj', '/C=KR/ST=Seoul/O=My Home/OU=My Home/CN=My Home/' ,
    // '-key', './private.pem',
    // '-new', '-sha256', '-out', 'certificate.csr'];
 
	// spawn('openssl', csrArgs, {stdio: 'pipe'}).on('exit', (code) => {
    //  	if (code !== 0) {
    //      	return reject(new Error("error generating csr: return code " + code));
    // 	}
	// });

});


app.all("/js_openssl", async (request,response) => {
	var rsakeyoptions = {
		encryption: {
			password: 'test',
			cipher: 'des3'
		},
		rsa_keygen_bits: 2048,
		rsa_keygen_pubexp: 65537,
		format: 'PKCS8'
	}

	// Root ca
	var cacsroptions = {
		hash: 'sha256',
		days: 5,
		subject: {
			countryName: 'KR',
			// stateOrProvinceName: 'Louisiana',
			// localityName: 'Slidell',
			// postalCode: '70458',
			// streetAddress: '1001 Gause Blvd.',
			organizationName: 'digitalzone',
			organizationalUnitName: [
				'IT'
			],
			commonName: [
				'digitalzone'
			],

		},
		extensions: {
			basicConstraints: {
				critical: true,
				CA: true,
				pathlen: 1
			},
			keyUsage: {
				critical: true,
				usages: [
					'digitalSignature',
					'keyEncipherment',
					'keyCertSign'
				]
			},
			extendedKeyUsage: {
				critical: true,
				usages: [
					'serverAuth',
					'clientAuth'
				]	
			}
		}
	}
	
	// 발급자 ca
	var csroptions = {
		hash: 'sha512',
		days : '1',
		subject: {
			countryName: 'KR',
			// stateOrProvinceName: 'Louisiana',
			// localityName: 'Slidell',
			// postalCode: '70458',
			// streetAddress: '1001 Gause Blvd.',
			organizationName: 'digitalzone2',  
			organizationalUnitName: 'digitalzone2',
			commonName: [
				'digitalzone2.com',
				'www.digitalzone2.com'
			],

			emailAddress: 'digitalzone2@com',
		},
		extensions: {
			// basic Constraints 확장은 인증서를 CA에 속하는 것으로 표시하여 다른 인증서에 서명할 수 있는 기능을 제공하는 데 사용됨
			// keyUsage이 시나리오에 대한 적절한 설정을 포함
			// CA: false -> 발급되는 인증서는 CA가 아니라는 뜻
			basicConstraints: {
				critical: true,
				CA: true,
				pathlen: 1
			},
			keyUsage: {
				//critical: false,
				usages: [
					'digitalSignature',
					'keyEncipherment'
				]
			},
			// extendedKeyUsage확장 은 TLS 클라이언트 및 서버 인증인 및 clientAuth만 지정
			extendedKeyUsage: {
				critical: true,
				usages: [
					'serverAuth',
					'clientAuth'
				]	
			},
			// SAN에 DNS 이름을 입력하지 않으면 CA / 브라우저 포럼 지침을 따르는 브라우저 및 기타 사용자 에이전트에서 인증서의 유효성이 검사되지 않음
			// 일반적으로 인증서가 사용되는 호스트 이름을 지정
			SANs: {
				DNS: [
					'digitalzone2.com',
					'www.digitalzone2.com'
				]
			}
		}
	}

	var cacrt2 = fs.readFileSync('./test111111111111111.crt');
	var cakey2 = fs.readFileSync('./test000000000000000.key');

	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
			openssl.CASignCSR(csr, csroptions, false, cacrt2 ,cakey2, 'test', function(err, crt, cmd) {
				if(err) console.log(err);
				console.log("cmd.files.config");
				console.log(cmd.files.config);
				console.log("crt");
				console.log(crt);
				fs.writeFile('./test4444444444444.crt',crt,function(err){
					if (err === null) {
						console.log('success'); 
					} else { 
						console.log('fail');
					}
				});
				openssl.getCertInfo(crt, function(err, attrs, cmd) {
					if(err) {
						console.log(err);
					} else {
						console.log(attrs);
					}
				});
			});
		});
	});

	const res = {
		success: "success",
		error: null
	}
		
	response.send(res);
	
	// openssl.generateRSAPrivateKey(rsakeyoptions, function(err, cakey, cmd) {
	// 	fs.writeFile('./test000000000000000.key',cakey,function(err){
	// 		if (err === null) {
	// 			console.log('success'); 
	// 		} else { 
	// 			console.log('fail');
	// 		}
	// 		});
	// 	openssl.generateCSR(cacsroptions, cakey, 'test', function(err, csr, cmd) {
	// 		if(err) {
	// 			console.log("asdfasfd");
	// 			console.log(err);
	// 		} else {
	// 			openssl.selfSignCSR(csr, cacsroptions, cakey, 'test', function(err, cacrt, cmd) {
	// 				if(err) {
	// 					console.log(err);
	// 				} else {
	// 									fs.writeFile('./test111111111111111.crt',cacrt,function(err){
	// 									if (err === null) {
	// 										console.log('success'); 
	// 									} else { 
	// 										console.log('fail');
	// 									}
	// 									});
	// 					openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
	// 						openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
	// 							openssl.CASignCSR(csr, csroptions, false, cacrt ,cakey, 'test', function(err, crt, cmd) {
	// 								if(err) console.log(err);
	// 								console.log(cmd.files.config);
	// 								console.log(crt);
	// 								fs.writeFile('./test222222222222.crt',crt,function(err){
	// 									if (err === null) {
	// 										console.log('success'); 
	// 									} else { 
	// 										console.log('fail');
	// 									}
	// 								});
	// 								openssl.getCertInfo(crt, function(err, attrs, cmd) {
	// 									if(err) {
	// 										console.log(err);
	// 									} else {
	// 										console.log(attrs);
	// 									}
	// 								});
	// 							});
	// 						});
	// 					});
	// 				}
	// 			});
	// 		}
	// 	});
	// });


});


// http:/localhost:5000/ 경로로 접근시
app.all("/xxx", async (request,response) => {

	const x509 = new X509Certificate(fs.readFileSync('./test4444444444444.crt'));

	/**
	 * 
	 * 이 인증서에 포함된 발급자 ID를 가져오는 중입니다.
	 * by using x509.issuer api
	 * 
	 */
	const value1 = x509.issuer
  
	// Display the result
	console.log("issuer(Ca 정보) : \n" + value1)

	/**
	 * 
	 * 인코딩된 X509 인증서가 인증 기관(ca) 인증서인지 여부를 확인하는 데 사용되는
	 * 암호화 모듈 내 클래스 X509Certificate의 내장 애플리케이션 프로그래밍 인터페이스
	 * by using x509.ca api
	 * 
	 */
	const value2 = x509.ca
  
	// display the result
	if(value2)
	console.log("인증 기관(ca) 인증서인지 여부를 확인 : \nthis is a Certificate Authority (ca) certificate")
	else
	console.log("인증 기관(ca) 인증서인지 여부를 확인 : \nthis is not a Certificate Authority (ca) certificate")

	/**
	 * 
	 * 이 인증서의 만료 날짜를 가져옵니다.
	 * by using x509.validTo function
	 * 
	 */
	const value3 = x509.validTo
  
	// display the result
	console.log("만료 날짜 : \n" + value3)

	/**
	 * 
	 * 이 인증서가 주어진 공개 키로 서명되었는지 확인
	 * by using x509.verify() function
	 * 
	 */
	const value4 = x509.verify(x509.publicKey)

	/**
	 * 
	 * 이 인증서에 포함된 주제를 가져옵니다.
	 * by using x509.subject function
	 * 
	 */
	const value5 = x509.subject
  
	// display the result
	console.log("subject(발급자 정보) : \n" + value5)  

	/**
	 * 
	 * 이 인증서에 포함된 주제를 가져옵니다.
	 * by using x509.subject function
	 * 
	 */
	 const value6 = x509.fingerprint256
  
	// display the result
	console.log("고유식별번호 : \n" + value6)  
 


	

	const res = {
		success: "success",
		error: null
	}
		
	response.send(res);
});
