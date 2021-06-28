package ocsp

import(
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"github.com/zzylydx/zcrypto/x509/pkix"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// 参考：https://github.com/cloudflare/cfssl/blob/master/certdb/ocspstapling/ocspstapling.go

// sctExtOid is the OID of the OCSP Stapling SCT extension (see section 3.3. of RFC 6962).
var sctExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

type NewParsedAndRawSCT struct {
	Raw []byte
	Parsed *ct.SignedCertificateTimestamp
}

// SerializeSCTList serializes a list of SCTs.
func SerializeSCTList(sctList []ct.SignedCertificateTimestamp) ([]byte, error) {
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range sctList {
		sctBytes, err := cttls.Marshal(sct)
		if err != nil {
			return nil, err
		}
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sctBytes})
	}
	return cttls.Marshal(list)
}

// DeserializeSCTList deserializes a list of SCTs.
func DeserializeSCTList(serializedSCTList []byte) (int,int,[]NewParsedAndRawSCT, error) {
	var sctLen int = 0
	var sctNum int = 0

	var sctList ctx509.SignedCertificateTimestampList
	rest, err := cttls.Unmarshal(serializedSCTList, &sctList)
	if err != nil {
		return sctLen,sctNum,nil, err
	}
	if len(rest) != 0 {
		return sctLen,sctNum,nil,errors.New("serialized SCT list contained trailing garbage")
	}
	list := make([]NewParsedAndRawSCT, len(sctList.SCTList))
	for i, serializedSCT := range sctList.SCTList {
		sctLen += len(serializedSCT.Val)
		var npars NewParsedAndRawSCT
		var sct ct.SignedCertificateTimestamp
		rest, err := cttls.Unmarshal(serializedSCT.Val, &sct)
		if err != nil {
			return sctLen,sctNum,nil, err
		}
		if len(rest) != 0 {
			return sctLen,sctNum,nil, errors.New("serialized SCT contained trailing garbage")
		}
		npars.Raw = serializedSCT.Val
		npars.Parsed = &sct
		list[i] = npars
	}
	sctNum = len(list)
	return sctLen,sctNum,list, nil
}

// 将string格式转为 Response结构体
func ConvertResponse(stringResponse string)(*Response,error) {
	der, err_base64_encoded:= base64.StdEncoding.DecodeString(stringResponse)
	if err_base64_encoded != nil{
		return nil, err_base64_encoded
	}
	// 解析response
	response, err_parse_der := ParseResponseForCert(der,nil,nil)
	if err_parse_der != nil {
		return nil,err_parse_der
	}

	return response,nil

}

// 解析传递过来的ocsp response,解析得到sct by ocsp stapling
func ParseSCTListFromOcspResponse(response *Response)(int,int,[]NewParsedAndRawSCT,error){
	// 将response中的sct扩展提取出来
	var sctExt pkix.Extension
	for _,ext := range response.Extensions {
		if ext.Id.Equal(sctExtOid){
			sctExt = ext
			break
		}
	}

	// 提取sct
	sctlist_byte := sctExt.Value

	// 反序列化为signed certificate timestamp
	var sctList []NewParsedAndRawSCT
	var sctLen int = 0
	var sctNum int = 0
	var err_sct_seri error
	var err_end error
	if numBytes := len(sctlist_byte); numBytes != 0 {
		var serializedSCTList []byte
		rest := make([]byte, numBytes)
		copy(rest,sctlist_byte)
		for len(rest) != 0 {
			rest, err_sct_seri = asn1.Unmarshal(rest, &serializedSCTList)
			if err_sct_seri != nil {
				return sctLen,sctNum,nil,err_sct_seri
			}
		}
		sctLen,sctNum,sctList,err_end = DeserializeSCTList(serializedSCTList)
	}

	return sctLen,sctNum,sctList, err_end
}

/*
	下面两个函数用于webmail study
 */

// DeserializeSCTList deserializes a list of SCTs. copy of DeserializeSCTList
func DeserializeSCTListByte(serializedSCTList []byte) ([][]byte, error) {
	var sctList ctx509.SignedCertificateTimestampList
	var sctListByte [][]byte
	rest, err := cttls.Unmarshal(serializedSCTList, &sctList)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil,errors.New("serialized SCT list contained trailing garbage")
	}
	// 添加sct 到list里面
	for _, serializedSCT := range sctList.SCTList {
		sctListByte = append(sctListByte,serializedSCT.Val)
	}

	return sctListByte, nil
}

// 解析传递过来的ocsp response,解析得到sct by ocsp stapling
func ParseSCTListFromOcspResponseByte(response *Response)([][]byte, error){
	var SctListByte [][]byte
	// 将response中的sct扩展提取出来
	var sctExt pkix.Extension
	for _,ext := range response.Extensions {
		if ext.Id.Equal(sctExtOid){
			sctExt = ext
			break
		}
	}

	// 提取sct
	sctlistByte := sctExt.Value

	var errSctSeri error
	var err_end error
	if numBytes := len(sctlistByte); numBytes != 0 {
		var serializedSCTList []byte
		rest := make([]byte, numBytes)
		copy(rest,sctlistByte)
		for len(rest) != 0 {
			rest, errSctSeri = asn1.Unmarshal(rest, &serializedSCTList)
			if errSctSeri != nil {
				return nil, errSctSeri
			}
		}
		SctListByte, err_end = DeserializeSCTListByte(serializedSCTList)
		if err_end != nil {
			return nil, err_end
		}
	}

	return SctListByte, nil
}