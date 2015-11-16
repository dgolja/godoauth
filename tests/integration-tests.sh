#!/bin/bash

function check_dependency {
	for c in docker-compose docker openssl awk sed; do
		# check if all binary are available for the test
		if [[ -z $(command -v $c) ]]; then
			echo "Missing ${c} binary ... Aborting ..."
			exit 1
		fi
	done
}

function create_dirs {
	for d in data certs; do
		if [[ ! -d $d ]]; then
			echo "Creating ${d} dir..."
			mkdir $d
		fi
	done
}
#generate new tests certs if nothing there
function create_certs {
	if [[ ! -f certs/server.pem ]]; then
		echo "Generating fresh certs in certs/"
		cd certs
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.pem \
		-subj "/C=AU/ST=NSW/L=Sydney/O=Godoauth/CN=Token"
		cd ..
	fi
}

function populate_vault {
	#configure vault with test data
	docker exec tests_vault_1 vault init -key-shares=1 -key-threshold=1 -address=http://localhost:8200 > vault-creds.txt
	cat vault-creds.txt | egrep ^Key | awk '{print $3}' | xargs docker exec tests_vault_1 vault unseal -address=http://localhost:8200
	cat vault-creds.txt | egrep ^Initial | awk '{print $4}' | xargs docker exec tests_vault_1 vault auth -address=http://localhost:8200
	
	docker exec tests_vault_1 vault mount -address=http://localhost:8200 -path=registry generic
	
	docker exec tests_vault_1 vault write -address=http://localhost:8200 registry/foo \
	password=bar access="repository:foo/bar:*"
	
	docker exec tests_vault_1 vault write -address=http://localhost:8200 registry/bar \
	password=foo access="repository:bar/foo:*"
	
	docker exec tests_vault_1 vault mounts -address=http://localhost:8200
	
	#fix vault config key
	cat vault-creds.txt | egrep ^Initial | awk '{print $4}' | xargs -I {} sed -i 's/    auth_token:.*$/    auth_token: {}/' config.yml
	docker restart tests_godoauth_1
}

function pass {

	if [[ $? != "0" ]]; then
		echo "fail but should pass"
		exit
	fi
}

function fail {
	if [[ $? == "0" ]]; then
		echo "pass but should fail"
		exit
	fi
}

# we should use some smarter tool than that :) but for the docker meetup should be enough
function tests {
	echo
	echo "Logging as foo user"
	docker login --username=foo --password=bar --email=foo@bar.org localhost:5000
	pass

	echo
	echo "Logging as bar with wrong password"
	docker login --username=bar --password=wrong --email=bar@wrong.org localhost:5000
	fail

	echo
	echo "Logging as bar user"
	docker login --username=bar --password=foo --email=bar@foo.org localhost:5000
	pass

	echo
	echo "Pulling busybox image"
	docker pull busybox
	timpe_stamp=$(date "+%Y%m%d%H%M")
	echo
	echo "Tag busybox with localhost:5000/bar/foo:${timpe_stamp}"
	docker tag busybox localhost:5000/bar/foo:${timpe_stamp}

	echo
	echo "Push image localhost:5000/bar/foo:${timpe_stamp}"
	docker push localhost:5000/bar/foo:${timpe_stamp}
	pass

	echo ""
}


check_dependency
create_dirs
create_certs
rm -rf ~/.docker/

# clean testing env
if [[ ${1} == "clean" ]]; then
	rm -rf data/
	rm -rf certs/
	docker-compose stop
	docker-compose rm -f
	exit 0
fi

if [[ ${1} == "rm" ]]; then
	rm -rf data/
	rm -rf certs/
	docker-compose stop
	docker-compose rm -f
	docker rmi tests_godoauth
	exit 0
fi

#start docker compose environment
docker-compose up -d

if [[ $? != 0 ]]; then
	echo "Something went wrong while starting docker-compose ... Check log"
	exit 2
fi

sleep 1
populate_vault

if [[ ${1} == "tests" ]]; then
	tests
fi


