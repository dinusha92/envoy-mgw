// Artifacts.go will retrive the data of the artifacts related to the filter chains.
// For example it could be API definitions, configuration files related to filters.

package controller

import (
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	oapi3 "github.com/getkin/kin-openapi/openapi3"
)

// This command will read the API definition from the mounted location.
// Implementation has been done assuming API definitions resides in <home/artifacts/apis location.
// Input parameters
//	- file location of the file to be read
// Return
//	- []byte of the read API definition.
//	- error if occurred when reading the file

func readFile(file string) ([]byte, error) {
	cont, err := ioutil.ReadFile(file)
	//if reading fails
	if err != nil {
		log.Warnf("Error in reading the file %v: error - %v", file, err)
	}

	return cont, err
}


func readApis() ([]oapi3.Swagger , error) {

	//Reading the files in the API directory
	ff, err := ioutil.ReadDir("./artifacts/apis")

	//if reading directory fails,
	if err != nil {
		log.Warnf("Error while reading the directory - %v", err)
		return nil, err
	}
	var apis = make([]oapi3.Swagger, len(ff))
	for i, f := range ff {
		cont, err := readFile("./artifacts/apis/" + f.Name())
		if err != nil {
			//Handle error
		}
		swagger, err := oapi3.NewSwaggerLoader().LoadSwaggerFromData(cont)
			apis[i] = *swagger
	}

	return apis,nil
}