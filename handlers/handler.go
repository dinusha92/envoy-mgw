//package handlers
//
//import (
//	"envoy-test-filter/jwt"
//     api3 "github.com/getkin/kin-openapi/openapi3"
//	"log"
//)
//
//func getSwagger(filepath string) {
//	//error is already handled
//	content, _ := jwt.ReadFile(filepath)
//	swagger, err := api3.NewSwaggerLoader().LoadSwaggerFromData(content)
//
//	if err != nil {
//		//Error occurred while loading swagger file
//	}
//
//	log.Printf()
//}
