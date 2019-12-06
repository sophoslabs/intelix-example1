package file_integrity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/zoltanosvath/nmapbeat/config"
)

const (
	malwareLookupPath = "/lookup/files/v1"
	staticLookupPath  = "/analysis/file/static/v1"
	dynamicLookupPath = "/analysis/file/dynamic/v1"
	reportPathPart    = "reports"
)

// --------------------------------------------------------------------------------------
type JobStatus string

const (
	IN_PROGRESS JobStatus = "IN_PROGRESS"
	SUCCESS     JobStatus = "SUCCESS"
	ERROR       JobStatus = "ERROR"
)

type Report struct {
	// Common fields
	Submission      string
	AnalysisType    string
	AnalysisSubject interface{}
	Score           int
	// Static analysis fields
	AnalysisSummary    interface{} `json:"analysis_summary,omitempty"`
	ContainerAnalysis  interface{} `json:"container_analysis,omitempty"`
	Detection          interface{} `json:"detection,omitempty"`
	DocumentAnalysis   interface{} `json:"document_analysis,omitempty"`
	MlAggregateResults interface{} `json:"ml_aggregate_results,omitempty"`
	MlFile             interface{} `json:"ml_file,omitempty"`
	MlFilepath         interface{} `json:"ml_filepath,omitempty"`
	MlInputs           interface{} `json:"ml_inputs,omitempty"`
	PeAnalysis         interface{} `json:"pe_analysis,omitempty"`
	Reputation         interface{} `json:"reputation,omitempty"`
	Target             interface{} `json:"target,omitempty"`
	// Dynamic analysis Fields
	MaliciousActivity        interface{}    `json:"malicious_activity,omitempty"`
	MaliciousClassifications interface{}    `json:"malicious_classifications,omitempty"`
	DetonationInfo           interface{}    `json:"detonation_info,omitempty"`
	Files                    interface{}    `json:"files,omitempty"`
	Processes                interface{}    `json:"processes,omitempty"`
	Registry                 interface{}    `json:"registry,omitempty"`
	Network                  interface{}    `json:"network,omitempty"`
	Screenshots              []string       `json:"screenshots,omitempty"`
	ScreenshotMap            map[int]string `json:"screenshot,omitempty"`
	ActivityTree             interface{}    `json:"activity_tree,omitempty"`
}

type AnalysisReport struct {
	CorellationId string        `json:"corellationId"`
	RequestId     string        `json:"requestId"`
	JobStatus     JobStatus     `json:"jobStatus"`
	JobId         string        `json:"jobId"`
	Report        Report        `json:"report"`
	AnalysisStats AnalysisStats `json:"analysis_stats"`
}

type AuthenticationResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	ExpiresAt   time.Time
}

type FileLookupResponse struct {
	CorellationId   string        `json:"corellationId"`
	RequestId       string        `json:"requestId"`
	ReputationScore int           `json:"reputationScore"`
	DetectionName   string        `json:"detectionName"`
	Ttl             int           `json:"ttl"`
	AnalysisStats   AnalysisStats `json:"analysis_stats"`
}

type ErrorResponse struct {
	CorellationId string `json:"corellationId"`
	RequestId     string `json:"requestId"`
	Error         string `json:"error"`
	Message       string `json:"message"`
	CreatedAt     string `json:"createdAt"`
}

// --------------------------------------------------------------------------------------

type AnalysisStats struct {
	TotalSeconds float64     `json:"total_seconds"`
	QueryStats   []QueryStat `json:"query_stats"`
}

type QueryType string

const (
	MALWARE        QueryType = "malware"
	STATIC_QUERY   QueryType = "static"
	STATIC_REPORT  QueryType = "static_report"
	DYNAMIC_QUERY  QueryType = "dynamic"
	DYNAMIC_REPORT QueryType = "dynamic_report"
)

type QueryStat struct {
	QueryType QueryType `json:"query_type"`
	Seconds   float64   `json:"total_seconds"`
}

func (stats *AnalysisStats) AddQueryStat(url *url.URL, d time.Duration) {
	var queryType QueryType
	switch {
	case strings.Contains(url.Path, malwareLookupPath):
		queryType = MALWARE
	case strings.Contains(url.Path, staticLookupPath):
		if strings.Contains(url.Path, reportPathPart) {
			queryType = STATIC_REPORT
		} else {
			queryType = STATIC_QUERY
		}
	case strings.Contains(url.Path, dynamicLookupPath):
		if strings.Contains(url.Path, reportPathPart) {
			queryType = DYNAMIC_REPORT
		} else {
			queryType = DYNAMIC_QUERY
		}
	default:
		panic(fmt.Errorf("Not recognized url: %v", url.String()))
	}

	stats.QueryStats = append(stats.QueryStats, QueryStat{QueryType: queryType, Seconds: d.Seconds()})
}

// --------------------------------------------------------------------------------------
type AnalysisType string

const (
	STATIC  AnalysisType = "static"
	DYNAMIC AnalysisType = "dynamic"
)

// --------------------------------------------------------------------------------------

// TODO: move this to config??
var analysisTriggeringActions = map[Action]bool{
	Created:     true,
	Updated:     true,
	InitialScan: true,
	//Moved:       true,
}

func ActionTriggersAnalysis(action Action) bool {
	for _, a := range action.InAnyOrder() {
		if found := analysisTriggeringActions[a]; found {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------------------
type IntelixScanner interface {
	MalwareLookup(sha256 Digest) (*FileLookupResponse, error)
	Analysis(analysisType AnalysisType, size uint64, filePath string) (*AnalysisReport, error)
}

type Intelix struct {
	config       *IntelixConfig
	client       *http.Client
	encodedCreds string
	token        *AuthenticationResponse
	log          *logp.Logger
}

func NewIntelix(c *IntelixConfig) (IntelixScanner, error) {
	timeout := time.Duration(c.QueryTimeout) * time.Second
	intelix := Intelix{
		config:       c,
		client:       &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: getProxyFunc(c.Urls.Proxy)}},
		encodedCreds: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", c.Credentials.ClientId, c.Credentials.ClientSecret))),
		log:          logp.NewLogger("intelix"),
	}

	return &intelix, nil
}

func (i *Intelix) Analysis(analysisType AnalysisType, size uint64, filePath string) (*AnalysisReport, error) {
	c := i.getAnalysisConfig(analysisType)

	i.log.Infof("Starting %v analysis of %v", analysisType, filePath)

	if size < c.MinSize {
		i.log.Infof("Skipping %v analyis for '%v', size %v is below threshold %v", analysisType, filePath, size, c.MinSize)
		return nil, nil
	}
	if size > c.MaxSize {
		i.log.Infof("Skipping %v analyis for '%v', size %v is abowe threshold %v", analysisType, filePath, size, c.MaxSize)
		return nil, nil
	}

	url, err := i.getAnalysisUrl(analysisType)
	if err != nil {
		return nil, err
	}

	pollInterval := time.Duration(c.ReportPollInterval) * time.Second

	req, err := newfileUploadRequest(url, nil, "file", filePath)
	if err != nil {
		return nil, err
	}

	i.log.Debugf("Sending '%v' to '%v'", filePath, url)

	analysisStart := time.Now()
	analysisStats := AnalysisStats{
		QueryStats: []QueryStat{},
	}

	analysisDeadline := time.Now().Add(time.Duration(c.AnalysisTimeout) * time.Second)

	var reportUrl string
	for {
		if time.Now().After(analysisDeadline) {
			return nil, fmt.Errorf("%v analysis of '%v' timed out", analysisType, filePath)
		}

		body, duration, err := i.doSlapRequest(req)
		if err != nil {
			return nil, err
		}

		analysisStats.AddQueryStat(req.URL, duration)

		i.log.Debugf("Lookup body: %v", string(body))

		var analysisReport AnalysisReport
		err = json.Unmarshal(body, &analysisReport)
		if err != nil {
			return nil, err
		}

		// TODO: verify if lookupResult seems valid (Unmarshal does not validate, just leaves fields empty)
		i.log.Debugf("Analysis report: %+v", analysisReport)

		switch analysisReport.JobStatus {
		case IN_PROGRESS:
			i.log.Infof("Waiting %v seconds for %v analysis of %v", pollInterval, analysisType, filePath)
			time.Sleep(pollInterval)

			if reportUrl == "" {
				if analysisReport.JobId == "" {
					return nil, fmt.Errorf("Received no JobId in response: %+v", analysisReport)
				}
				reportUrl = fmt.Sprintf("%v/%v/%v", url, reportPathPart, analysisReport.JobId)
			}
			req, err = http.NewRequest("GET", reportUrl, nil)
			if err != nil {
				return nil, err
			}
			continue
		case ERROR, SUCCESS:
			analysisStats.TotalSeconds = time.Since(analysisStart).Seconds()
			analysisReport.AnalysisStats = analysisStats

			replaceScreenshotArrayWithMap(&analysisReport)
			i.log.Infof("Successful %v analysis of %v", analysisType, filePath)
			return &analysisReport, nil
		default:
			return nil, fmt.Errorf("Invalid JobStatus received: %v", analysisReport.JobStatus)
		}
	}
}

func (i *Intelix) getAnalysisConfig(analysisType AnalysisType) *IntelixAnalysisCOnfig {
	switch analysisType {
	case STATIC:
		return &i.config.StaticAnalysisConig
	case DYNAMIC:
		return &i.config.DynamicAnalysisConfig
	default:
		panic(fmt.Errorf("Invalid analysis type: %v", analysisType))
	}
}

func replaceScreenshotArrayWithMap(a *AnalysisReport) {
	if len(a.Report.Screenshots) == 0 {
		return
	}

	var screenshots = make(map[int]string)
	for i, sc := range a.Report.Screenshots {
		screenshots[i] = sc
	}

	a.Report.Screenshots = nil
	a.Report.ScreenshotMap = screenshots
}

func (i *Intelix) getAnalysisUrl(analysisType AnalysisType) (string, error) {
	var urlPath string
	switch analysisType {
	case STATIC:
		urlPath = staticLookupPath
	case DYNAMIC:
		urlPath = dynamicLookupPath
	default:
		panic(fmt.Errorf("Invalid analysis type: %v", analysisType))
	}

	url := fmt.Sprintf("%v%v", i.config.Urls.IntelixUrl, urlPath)
	return url, nil
}

func newfileUploadRequest(uri string, params map[string]string, paramName, path string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, err
}

func (i *Intelix) MalwareLookup(sha256 Digest) (*FileLookupResponse, error) {
	url := fmt.Sprintf("%v%v/%v", i.config.Urls.IntelixUrl, malwareLookupPath, sha256)

	i.log.Infof("Malware lookup: %v", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	body, duration, err := i.doSlapRequest(req)
	if err != nil {
		return nil, err
	}

	i.log.Debugf("Lookup body: %v", string(body))

	var lookupResult FileLookupResponse
	err = json.Unmarshal(body, &lookupResult)
	if err != nil {
		return nil, err
	}

	lookupResult.AnalysisStats = AnalysisStats{
		TotalSeconds: duration.Seconds(),
		QueryStats: []QueryStat{
			QueryStat{QueryType: MALWARE, Seconds: duration.Seconds()},
		},
	}

	// TODO: verify if lookupResult seems valid (Unmarshal does not validate, just leaves fields empty)
	i.log.Infof("Malware lookup succeded: %v", url)
	i.log.Debugf("Malware lookup result: %+v", lookupResult)

	return &lookupResult, nil
}

func (i *Intelix) doSlapRequest(req *http.Request) ([]byte, time.Duration, error) {
	if err := i.setToken(); err != nil {
		return nil, 0, err
	}

	i.log.Debugf("Request start:    %v", req.URL.String())

	req.Header.Set("Authorization", fmt.Sprintf("%v", i.token.AccessToken))
	// req.Header.Set("Authorization", fmt.Sprintf("%v %v", i.token.TokenType, i.token.AccessToken))

	requestStart := time.Now()

	resp, err := i.client.Do(req)

	requestDuration := time.Since(requestStart)

	if err != nil {
		return nil, requestDuration, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, requestDuration, err
	}

	if resp.StatusCode >= 300 {
		url := req.URL.String()
		if errorResponse, _ := unmarshalError(body); errorResponse != nil {
			return nil, requestDuration, fmt.Errorf("%v failed for '%v': %+v", req.Method, url, errorResponse)
		}
		return nil, requestDuration, fmt.Errorf("%v failed for '%v': %v", req.Method, url, string(body))
	}

	i.log.Debugf("Request finished: %v", req.URL.String())

	return body, requestDuration, nil
}

func unmarshalError(body []byte) (*ErrorResponse, error) {
	var errorResponse ErrorResponse
	err := json.Unmarshal(body, &errorResponse)
	if err != nil {
		return nil, err
	}

	return &errorResponse, nil
}

func (i *Intelix) setToken() error {
	if i.token != nil && time.Until(i.token.ExpiresAt) > time.Duration(30)*time.Second {
		return nil
	}

	i.log.Infof("Requesting auth token from %v", i.config.Urls.AuthUrl)

	req, err := http.NewRequest("POST", i.config.Urls.AuthUrl, bytes.NewBuffer([]byte("grant_type=client_credentials")))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %v", i.encodedCreds))

	resp, err := i.client.Do(req)
	if err != nil {
		i.log.Errorf("Error during token request: %v", err)
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var token AuthenticationResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return err
	}

	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	i.token = &token

	i.log.Info("Requesting auth token successful")
	return nil
}

func getProxyFunc(proxyUrl string) (proxyFunc func(*http.Request) (*url.URL, error)) {
	if proxyUrl != "" {
		url, err := config.ParseProxyURL(proxyUrl)
		if err != nil {
			panic(err)
		}

		proxyFunc = http.ProxyURL(url)
	}

	return proxyFunc
}

// copied from: elastic/beats/libbeat/outputs/elasticsearch/url.go
func ParseProxyURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}

	url, err := url.Parse(raw)
	if err == nil && strings.HasPrefix(url.Scheme, "http") {
		return url, err
	}

	// Proxy was bogus. Try prepending "http://" to it and
	// see if that parses correctly.
	return url.Parse("http://" + raw)
}
