// Copyright 2017 Xiaomi, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package graph

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/gin-gonic/gin"
	cmodel "github.com/open-falcon/falcon-plus/common/model"
	h "github.com/open-falcon/falcon-plus/modules/api/app/helper"
	m "github.com/open-falcon/falcon-plus/modules/api/app/model/graph"
	u "github.com/open-falcon/falcon-plus/modules/api/app/utils"
)

type APIGrafanaMainQueryInputs struct {
	Limit int    `json:"limit"  form:"limit"`
	Query string `json:"query"  form:"query"`
}

type APIGrafanaMainQueryOutputs struct {
	Expandable bool   `json:"expandable"`
	Text       string `json:"text"`
}

//for return a host list for api test
func repsonseDefault(limit int) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	//for get right table name
	enpsHelp := m.Endpoint{}
	enps := []m.Endpoint{}
	db.Graph.Table(enpsHelp.TableName()).Limit(limit).Scan(&enps)
	for _, h := range enps {
		result = append(result, APIGrafanaMainQueryOutputs{
			Expandable: true,
			Text:       h.Endpoint,
		})
	}
	return
}

//for find host list & grafana template searching, regexp support
func responseHostsRegexp(limit int, regexpKey string) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	//for get right table name
	enpsHelp := m.Endpoint{}
	enps := []m.Endpoint{}
	db.Graph.Table(enpsHelp.TableName()).Where("endpoint regexp ?", regexpKey).Limit(limit).Scan(&enps)
	for _, h := range enps {
		result = append(result, APIGrafanaMainQueryOutputs{
			Expandable: true,
			Text:       h.Endpoint,
		})
	}
	return
}

//for resolve mixed query with endpoint & counter of query string
func cutEndpointCounterHelp(regexpKey string) (hosts []string, counter string) {
	r, _ := regexp.Compile("^{?([^#}]+)}?#(.+)")
	matchedList := r.FindAllStringSubmatch(regexpKey, 1)
	if len(matchedList) != 0 {
		if len(matchedList[0]) > 1 {
			//get hosts
			hostsTmp := matchedList[0][1]
			counterTmp := matchedList[0][2]
			hosts = strings.Split(hostsTmp, ",")
			counter = strings.Replace(counterTmp, "#", "\\.", -1)
		}
	} else {
		log.Errorf("grafana query inputs error: %v", regexpKey)
	}
	return
}

func expandableChecking(counter string, counterSearchKeyWord string) (expsub string, needexp bool) {
	re := regexp.MustCompile("(\\.\\+|\\.\\*)\\s*$")
	counterSearchKeyWord = re.ReplaceAllString(counterSearchKeyWord, "")
	counterSearchKeyWord = strings.Replace(counterSearchKeyWord, "\\.", ".", -1)
	expCheck := strings.Replace(counter, counterSearchKeyWord, "", -1)
	if expCheck == "" {
		needexp = false
		expsub = expCheck
	} else {
		needexp = true
		re = regexp.MustCompile("^\\.")
		expsubArr := strings.Split(re.ReplaceAllString(expCheck, ""), ".")
		switch len(expsubArr) {
		case 0:
			expsub = ""
		case 1:
			expsub = expsubArr[0]
			needexp = false
		default:
			expsub = expsubArr[0]
			needexp = true
		}
	}
	return
}

/* add additional items (ex. $ & %)
   $ means metric is stop on here. no need expand any more.
   % means a wirecard string.
   also clean defecate metrics
*/
func addAddItionalItems(items []APIGrafanaMainQueryOutputs, regexpKey string) (result []APIGrafanaMainQueryOutputs) {
	flag := false
	mapset := hashmap.New()
	for _, i := range items {
		if !i.Expandable {
			flag = true
		}
		if val, exist := mapset.Get(i.Text); exist {
			if val != i.Expandable && i.Expandable {
				mapset.Put(i.Text, i.Expandable)
			}
		} else {
			mapset.Put(i.Text, i.Expandable)
		}
	}
	result = make([]APIGrafanaMainQueryOutputs, mapset.Size())
	for idx, ctmp := range mapset.Keys() {
		c := ctmp.(string)
		val, _ := mapset.Get(c)
		result[idx] = APIGrafanaMainQueryOutputs{
			Text:       c,
			Expandable: val.(bool),
		}
	}
	if flag {
		result = append(result, APIGrafanaMainQueryOutputs{
			Text:       "$",
			Expandable: false,
		})
	}
	if len(strings.Split(regexpKey, "\\.")) > 0 {
		result = append(result, APIGrafanaMainQueryOutputs{
			Text:       "%",
			Expandable: false,
		})
	}
	return
}

func findEndpointIdByEndpointList(hosts []string) []int64 {
	//for get right table name
	enpsHelp := m.Endpoint{}
	enps := []m.Endpoint{}
	db.Graph.Table(enpsHelp.TableName()).Where("endpoint in (?)", hosts).Scan(&enps)
	hostIds := make([]int64, len(enps))
	for indx, h := range enps {
		hostIds[indx] = int64(h.ID)
	}
	return hostIds
}

//for reture counter list of endpoints
func responseCounterRegexp(regexpKey string) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	hosts, counter := cutEndpointCounterHelp(regexpKey)
	if len(hosts) == 0 || counter == "" {
		return
	}
	hostIds := findEndpointIdByEndpointList(hosts)
	//if not any endpoint matched
	if len(hostIds) == 0 {
		return
	}
	idConcact, _ := u.ArrInt64ToString(hostIds)
	//for get right table name
	countHelp := m.EndpointCounter{}
	counters := []m.EndpointCounter{}
	db.Graph.Table(countHelp.TableName()).Where(fmt.Sprintf("endpoint_id IN (%s) AND counter regexp '%s'", idConcact, counter)).Scan(&counters)
	//if not any counter matched
	if len(counters) == 0 {
		return
	}
	for _, c := range counters {
		expsub, needexp := expandableChecking(c.Counter, counter)
		result = append(result, APIGrafanaMainQueryOutputs{
			Text:       expsub,
			Expandable: needexp,
		})
	}
	result = addAddItionalItems(result, regexpKey)
	return
}

func GrafanaMainQuery(c *gin.Context) {
	inputs := APIGrafanaMainQueryInputs{}
	inputs.Limit = 1000
	inputs.Query = "!N!"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	log.Debugf("got query string: %s", inputs.Query)
	output := []APIGrafanaMainQueryOutputs{}
	if inputs.Query == "!N!" {
		output = repsonseDefault(inputs.Limit)
	} else if !strings.Contains(inputs.Query, "#") {
		output = responseHostsRegexp(inputs.Limit, inputs.Query)
	} else if strings.Contains(inputs.Query, "#") && !strings.Contains(inputs.Query, "#select metric") {
		output = responseCounterRegexp(inputs.Query)
	}
	c.JSON(200, output)
	return
}

type APIGrafanaRenderInput struct {
	Target        []string `json:"target" form:"target"  binding:"required"`
	From          int64    `json:"from" form:"from" binding:"required"`
	Until         int64    `json:"until" form:"until" binding:"required"`
	Format        string   `json:"format" form:"format"`
	MaxDataPoints int64    `json:"maxDataPoints" form:"maxDataPoints"`
	Step          int      `json:"step" form:"step"`
	ConsolFun     string   `json:"consolFun" form:"consolFun"`
}

func GrafanaRender(c *gin.Context) {
	inputs := APIGrafanaRenderInput{}
	//set default step is 60
	inputs.Step = 60
	inputs.ConsolFun = "AVERAGE"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	respList := []*cmodel.GraphQueryResponse{}
	for _, target := range inputs.Target {
		hosts, counter := cutEndpointCounterHelp(target)
		//clean characters
		log.Debug(counter)
		re := regexp.MustCompile("\\\\.\\$\\s*$")
		flag := re.MatchString(counter)
		counter = re.ReplaceAllString(counter, "")
		counter = strings.Replace(counter, "\\.%", ".+", -1)
		ecHelp := m.EndpointCounter{}
		counters := []m.EndpointCounter{}
		hostIds := findEndpointIdByEndpointList(hosts)
		if flag {
			db.Graph.Table(ecHelp.TableName()).Select("distinct counter").Where(fmt.Sprintf("endpoint_id IN (%s) AND counter = '%s'", u.ArrInt64ToStringMust(hostIds), counter)).Scan(&counters)
		} else {
			db.Graph.Table(ecHelp.TableName()).Select("distinct counter").Where(fmt.Sprintf("endpoint_id IN (%s) AND counter regexp '%s'", u.ArrInt64ToStringMust(hostIds), counter)).Scan(&counters)
		}
		if len(counters) == 0 {
			// 没有匹配到的继续执行，避免当grafana graph有多个查询时，其他正常的查询也无法渲染视图
			continue
		}
		counterArr := make([]string, len(counters))
		for indx, c := range counters {
			counterArr[indx] = c.Counter
		}
		for _, host := range hosts {
			for _, c := range counterArr {
				resp, err := fetchData(host, c, inputs.ConsolFun, inputs.From, inputs.Until, inputs.Step)
				if err != nil {
					log.Debugf("query graph got error with: %v", inputs)
				} else {
					respList = append(respList, resp)
				}
			}
		}
	}
	c.JSON(200, respList)
	return
}

// for return a tag list for api test
func tagResponseDefault(limit int) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	tagEnpHelp := m.TagEndpoint{}
	tagEnps := []m.TagEndpoint{}
	db.Graph.Table(tagEnpHelp.TableName()).Select("distinct tag").Limit(limit).Scan(&tagEnps)
	for _, h := range tagEnps {
		result = append(result, APIGrafanaMainQueryOutputs{
			Expandable: true,
			Text:       h.Tag,
		})
	}
	return
}



func tagResponse(regexKey string) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	tagEnpHelp := m.TagEndpoint{}
	tagEnps := []m.TagEndpoint{}
	tags := trimSplitHelper(regexKey, ",")
	db.Graph.Table(tagEnpHelp.TableName()).Where("tag in (*)", tags).Scan(&tagEnps)
	for _, h := range tagEnps {
		result = append(result, APIGrafanaMainQueryOutputs{
			Expandable: true,
			Text:       h.Tag,
		})
	}
	return
}

// for resolve mixed query with tag & endpoint & metric of query string
func cutTagEndpointMetricHelp(regexKey string) (tags []string, hosts []string, metrics []string) {
	r, _ := regexp.Compile("^(.*)##(.*)##(.*)")
	matchedList := r.FindAllStringSubmatch(regexKey, 1)
	if len(matchedList) != 0 {
		if len(matchedList[0]) > 1 {
			tagsTmp := matchedList[0][1]
			tagsTmp = strings.Replace(tagsTmp, "#", ".", -1)
			tags = trimSplitHelper(tagsTmp, ",")

			hostsTmp := matchedList[0][2]
			hostsTmp = strings.Replace(hostsTmp, "#", ".", -1)
			hosts = trimSplitHelper(hostsTmp, ",")

			metricsTmp := matchedList[0][3]
			metricsTmp = strings.Replace(metricsTmp, "#", ".", -1)
			metrics = trimSplitHelper(metricsTmp, ",")
		}
	} else {
		log.Errorf("grafana query inputs error: %v", regexKey)
	}
	log.Debug(tags)
	log.Debug(hosts)
	log.Debug(metrics)
	return
}

func trimSplitHelper(key string, split_key string) (keys []string) {
	keys = strings.Split(strings.TrimSpace(key), split_key)
	return
}

// tag, endpoint precision match
func findEndpointInByTagEndpointlist(tags []string, hosts []string) []int64 {
	enpsHelp := m.Endpoint{}
	enps := []m.Endpoint{}
	tagEnpsHelp := m.TagEndpoint{}
	tagEnps := []m.TagEndpoint{}

	// tags 表示必须满足所有，拿到所有的tag实体去找满足的endpoint -> 所有的 endpoint_id
	db.Graph.Table(tagEnpsHelp.TableName()).Where("tag in (?)", tags).Scan(&tagEnps)
	var endpointIds []int
	for _, tag := range tagEnps {
		endpointIds = append(endpointIds, tag.EndpointID)
	}

	if len(hosts) == 0 || hosts[0] == "" {
		// 没有指定 endpoint，取打了该tag 的所有endpoint
		db.Graph.Table(enpsHelp.TableName()).Where("id in (?)", endpointIds).Scan(&enps)
	} else {
		db.Graph.Table(enpsHelp.TableName()).Where("id in (?) and endpoint in (?)", endpointIds, hosts).Scan(&enps)
	}

	hostIds := make([]int64, len(enps))
	for indx, h := range enps {
		hostIds[indx] = int64(h.ID)
	}
	return hostIds
}

// for return metric list of endpoints
func responseMetricRegexp(regexKey string) (result []APIGrafanaMainQueryOutputs) {
	result = []APIGrafanaMainQueryOutputs{}
	tags, hosts, metrics := cutTagEndpointMetricHelp(regexKey)
	// may too much result, denied
	if len(hosts) == 0 && len(metrics) == 0 {
		return
	}
	// Precision match
	hostIds := findEndpointInByTagEndpointlist(tags, hosts)

	if len(hostIds) == 0 {
		return
	}
	idConcact, _ := u.ArrInt64ToString(hostIds)
	//for get right table name
	countHelp := m.EndpointCounter{}
	// todo: more sql efficient
	for _, metric := range metrics {
		counters := []m.EndpointCounter{}
		db.Graph.Table(countHelp.TableName()).Where(fmt.Sprintf("endpoint_id IN (%s) AND counter regexp '%s'", idConcact, metric)).Scan(&counters)
		for _, c := range counters {
			result = append(result, APIGrafanaMainQueryOutputs{
				Text:       c.Counter,
				Expandable: false,
			})
		}
	}
	//if not any counter matched
	if len(result) == 0 {
		return
	}
	result = addAddItionalItems(result, regexKey)
	return
}

func GrafanaTagQuery(c *gin.Context) {
	inputs := APIGrafanaMainQueryInputs{}
	inputs.Limit = 1000
	inputs.Query = "!N!"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	fmt.Println(inputs.Query)
	log.Debugf("got query string: %s", inputs.Query)
	output := []APIGrafanaMainQueryOutputs{}
	if inputs.Query == "!N!" || inputs.Query == ".*" {
		output = tagResponseDefault(inputs.Limit)
	} else if !strings.Contains(inputs.Query, "#") {
		output = tagResponse(inputs.Query)
	} else if strings.Contains(inputs.Query, "#") {
		output = responseMetricRegexp(inputs.Query)
	}
	c.JSON(200, output)
	return
}

func NewGrafanaRender(c *gin.Context) {
	inputs := APIGrafanaRenderInput{}
	//set default step is 60
	inputs.Step = 60
	inputs.ConsolFun = "AVERAGE"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	log.Debug(inputs)
	respList := []*cmodel.GraphQueryResponse{}
	for _, target := range inputs.Target {
		tags, hosts, metrics := cutTagEndpointMetricHelp(target)

		// 通过 tags + metrics 过滤出 counter，
		// 如果有 endpoint，优先对 endpoint 进行过滤
		// 如果有多个 metric，对多个 metric 进行拼接
		// 之后对 tag 做过滤，要同时满足所有的 tag -> 字符串拼接

		// region=beijing3,server_name=haproxy##downtime,ctime
		// 1. 获取到counter：
		// select * from endpoint_counter where (counter like '%region=beijing3%' and counter like '%server_name=haproxy%') and (counter like 'downtime/%' or counter like 'ctime/%')
		// 2. 获取到 endpoint：
		// 如果regexp 中提供endpoint，直接取即可；如果没有，从上述的endpoint_counter中取。
		ecHelp := m.EndpointCounter{}
		counters := []m.EndpointCounter{}

		enpHelp := m.Endpoint{}
		endpoints := []m.Endpoint{}

		// opt: make([]string, len(tags))
		var tagSlice []string
		if len(tags) > 0 && tags[0] != "" {
			for indx, tag := range tags {
				if indx > 0 {
					tagSlice = append(tagSlice, " and ")
				}
				tagSlice = append(tagSlice, fmt.Sprintf("counter like '%%%s%%'", tag))
			}
		}
		tagTmpSql := strings.Join(tagSlice, "")
		var metricSlice []string
		if len(metrics) > 0 && metrics[0] != "" {
			for indx, metric := range metrics {
				if indx > 0 {
					metricSlice = append(metricSlice, " or ")
				}
				metricSlice = append(metricSlice, fmt.Sprintf("counter like '%s/%%'", metric))
			}
		}
		metricTmpSql := strings.Join(metricSlice, "")
		var counterSql string
		if metricTmpSql != "" {
			counterSql = tagTmpSql + "and (" + metricTmpSql + ")"
		} else {
			counterSql = metricTmpSql
		}

		db.Graph.Table(ecHelp.TableName()).Select("distinct counter, endpoint_id").Where(counterSql).Scan(&counters)

		if len(hosts) > 0 && hosts[0] != "" {
			// 根据 hosts 获取 endpoint
			db.Graph.Table(enpHelp.TableName()).Where("endpoint in (?)", hosts).Scan(&endpoints)
		} else {
			// 根据counter sql 获取 endpoint_id -> endpoint
			var hostIds []int
			for _, counter := range counters {
				hostIds = append(hostIds, counter.EndpointID)
			}
			//log.Debug(hostIds)
			db.Graph.Table(enpHelp.TableName()).Where("id in (?)", hostIds).Scan(&endpoints)
		}

		//log.Debug(counters)
		//log.Debug(endpoints)

		if len(counters) == 0 {
			// 没有匹配到的继续执行，避免当grafana graph有多个查询时，其他正常的查询也无法渲染视图
			continue
		}
		counterArr := make([]string, len(counters))
		for indx, c := range counters {
			counterArr[indx] = c.Counter
		}

		for _, endpoint := range endpoints {
			for _, counter := range counters {
				resp, err := fetchData(endpoint.Endpoint, counter.Counter, inputs.ConsolFun, inputs.From, inputs.Until, inputs.Step)
				//log.Debug(resp)
				if err != nil {
					log.Debugf("query graph got error with: %v", inputs)
				} else {
					respList = append(respList, resp)
				}
			}
		}
	}
	c.JSON(200, respList)
	return
}

func GrafanaMultiQuery(c *gin.Context) {
	inputs := APIGrafanaMainQueryInputs{}
	inputs.Limit = 1000
	inputs.Query = "!N!"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	fmt.Println(inputs.Query)
	log.Debugf("got query string: %s", inputs.Query)
	output := []APIGrafanaMainQueryOutputs{}
	if inputs.Query == "!N!" || inputs.Query == ".*" || !strings.Contains(inputs.Query, "#") {
		output = typeResponseDefault(inputs.Limit)
	} else if strings.Contains(inputs.Query, "##") {
		output = multiTypeRegexp(inputs.Query, inputs.Limit)
	}
	c.JSON(200, output)
	return
}


func typeResponseDefault(limit int) (typeOutputs []APIGrafanaMainQueryOutputs) {
	typeOutputs = []APIGrafanaMainQueryOutputs{}
	typeTag := APIGrafanaMainQueryOutputs{Expandable: true, Text: "tag#",}
	typeOutputs = append(typeOutputs, typeTag)
	return
}

func tagRelatedCounterFilter(tags []string) (tagFilter string) {
	var tagSlice []string
	for _, tag := range tags {
		if tag == "*" {
			return
		}
		tagSlice = append(tagSlice, fmt.Sprintf("endpoint_counter.counter like '%%%s%%'", tag))
	}
	tagFilter = strings.Join(tagSlice, " and ")
	return
}

func tagRelatedTagFilter(tags []string) (tagFilter string) {
	for _, tag := range tags {
		if tag == "*" {
			return
		}
	}
	tagFilter = fmt.Sprintf("tag_endpoint.tag in (%s)", u.ArrStringsToStringMust(tags))
	return
}


func endpointRelatedEndpointFilter(endpoints []string) (endpointFilter string){
	for _, endpoint := range endpoints {
		if endpoint == "*" {
			return
		}
	}
	endpointFilter = fmt.Sprintf("endpoint.endpoint in (%s)", u.ArrStringsToStringMust(endpoints))
	return

}

func endpointRelatedEndpointExclude(endpoints []string) (endpointExclude string){
	if len(endpoints) == 0 {
		return
	}
	endpointExclude = fmt.Sprintf("endpoint.endpoint not in (%s)", u.ArrStringsToStringMust(endpoints))
	return
}

func metricRelatedCounterExclude(metrics []string) (metricExclude string) {
	var metricSlice []string
	for _, metric := range metrics {
		metricSlice = append(metricSlice, fmt.Sprintf("endpoint_counter.counter not regexp '^%s/'", metric))
	}
	metricExclude = strings.Join(metricSlice, " and ")
	return
}

func metricRelatedCounterFilter(metrics []string) (metricFilter string) {
	var metricSlice []string
	for _, metric := range metrics {
		metricSlice = append(metricSlice, fmt.Sprintf("endpoint_counter.counter like '%s/%%'", metric))
	}
	metricFilter = strings.Join(metricSlice, " or ")
	return
}


func multiTypeRegexp(regexKey string, limit int) (result []APIGrafanaMainQueryOutputs){
	result = []APIGrafanaMainQueryOutputs{}
	tags, endpoints, metrics, additionItem, err := parseMultiTypeHelp(regexKey)
	log.Debug(tags)
	log.Debug(endpoints)
	log.Debug(metrics)
	log.Debug(additionItem)
	log.Debug(err)
	if err != nil {
		return
	}
	if additionItem.Type == 0 {
		var typeString []string
		switch additionItem.Level {
		case 0:
			if len(tags) > 0 && tags[0] == "*"{
				typeString = []string{"endpoint#"}
			}else{
				typeString = []string{"tag#", "endpoint#"}
			}
		case 1:
			if len(endpoints) > 0 && endpoints[0] == "*" {
				typeString = []string{"metric#"}
			}else {
				typeString = []string{"endpoint#", "metric#"}
			}
		case 2:
			if len(metrics) > 0 && metrics[0] == "*" {
				typeString = []string {}
			}else {
				typeString = []string {"metric#"}
			}
			result = append(result, APIGrafanaMainQueryOutputs{
				Text: "!",
				Expandable: false,
			})
		default: typeString = []string{}
		}
		for _, str := range typeString {
			result = append(result, APIGrafanaMainQueryOutputs{
				Text: str,
				Expandable: true,
			})
		}
	} else {

		tagRes := []m.TagEndpoint{}

		enpRes := []m.Endpoint{}

		counterRes := []m.EndpointCounter{}
		switch additionItem.Level {
		case 0:
			// 返回所有其他 tag
			var tagFilter string
			if len(tags) > 0 {
				tagFilter = fmt.Sprintf("tag not in (%s)", u.ArrStringsToStringMust(tags))
			}
			db.Graph.Table("tag_endpoint").Select("distinct tag").Where(tagFilter).Limit(limit).Scan(&tagRes)
			// db.Graph.Table(tagHelp.TableName()).Select("distinct tag").Where("tag not in (?)", tags).Limit(limit).Scan(&tagRes)
			for _, tag := range tagRes {
				result = append(result, APIGrafanaMainQueryOutputs{
					Text: tag.Tag + "#",
					Expandable: true,
				})
			}

		case 1:
			// 返回 tags 下所有其他的 endpoint
			// select * from endpoint join tag_endpoint on endpoint.id = tag_endpoint.endpoint_id where endpoint.endpoint not in (?) and tag_endpoint.tag in (?)
			tagFilter := tagRelatedTagFilter(tags)
			endpointExclude := endpointRelatedEndpointExclude(endpoints)
			if tags[0] == "*" {
				db.Graph.Table("endpoint").Select("endpoint.endpoint").Where(endpointExclude).Limit(limit).Scan(&enpRes)
			} else {
				db.Graph.Table("endpoint").Select("endpoint.endpoint").
				Joins("join tag_endpoint on endpoint.id = tag_endpoint.endpoint_id").
				Where(tagFilter).Where(endpointExclude).Group("endpoint.id").
				Having("count(tag_endpoint.tag) = ?", len(tags)).
				Limit(limit).Scan(&enpRes)
			}

			for _, enp := range enpRes {
				result = append(result, APIGrafanaMainQueryOutputs{
					Text: enp.Endpoint + "#",
					Expandable: true,
				})
			}

		case 2:
			// 返回有 tags 且属于 endpoints 的其他 metric
			// select * from endpoint_counter join endpoint on endpoint.id = endpoint_counter.endpoint_id where endpoint.endpoint not in (?) and endpoint_counter like (?)

			tagFilter := tagRelatedCounterFilter(tags)
			endpointFilter := endpointRelatedEndpointFilter(endpoints)
			metricExclude := metricRelatedCounterExclude(metrics)

			db.Graph.Table("endpoint_counter").Select("substring_index(endpoint_counter.counter, '/', 1) as counter").
			Joins("join endpoint on endpoint_counter.endpoint_id = endpoint.id").
			Where(tagFilter).Where(endpointFilter).Where(metricExclude).
			Limit(limit).Scan(&counterRes)

			for _, counter := range counterRes {
				result = append(result, APIGrafanaMainQueryOutputs{
					Text: counter.Counter + "#",
					Expandable: true,
				})
			}

		}
	}
	log.Debug(result)

	//result = addAddItionalItems(result, regexKey)
	return
}


type APIAdditionItems struct {
	Type  int `json:"type"`
	Level int `json:"level"`
}


func validateTypeOrder(parts []string) (err error) {

	// 对偶数下标的元素进行顺序的检验: tag -> endpoint -> metric
	globalOrder := 0
	curOrder := 0
	for indx, t := range parts {
		if indx & 1 == 0 {
			switch t {
			case "tag":  curOrder = 0
			case "endpoint": curOrder = 1
			case "metric": curOrder = 2
			case "!": curOrder = 3
			default:
				return fmt.Errorf("bad grafana input query type: %s", t)
			}
		}
		if globalOrder > 2 {
			return fmt.Errorf("bad grafana input query after eof")
		}
		if curOrder >= globalOrder {
			globalOrder = curOrder
		} else {
			return fmt.Errorf("bad grafana input query order")
		}

	}
	return

}

func validateDataStarValue(parts []string) (err error) {

	// 对奇数下标的元素进行数值检查：metric中不能含有 *，tag / endpoint 中只能有一个是 * 值
	starCount := 0
	for index, part := range parts {
		if index & 1 != 0 {
			if part == "*" {
				starCount ++
			}
			if starCount > 1 {
				return fmt.Errorf("bad grafana input query multiply star")
			}
		}
	}
	return nil
}

func formatInputHelp(regexKey string) (formatParts []string, err error) {
	// 切除query 末尾的 .*
	re := regexp.MustCompile(`#\.\*$`)
	regexKey = re.ReplaceAllString(regexKey, "#")

	// 将grafana自带的 * 或者 编辑框中的 *# 统一成 *#
	// 等价于将 query 中的 *# 或者 *## 都统一成 *##
	re = regexp.MustCompile(`\*#{1,2}`)
	regexKey = re.ReplaceAllString(regexKey, "*##")

	// 切除末尾的 ##
	re = regexp.MustCompile(`##$`)
	regexKey = re.ReplaceAllString(regexKey, "")

	log.Debug(regexKey)

	// 切分 query
	parts := trimSplitHelper(regexKey, "##")

	for _, part := range parts {
		re = regexp.MustCompile(`#`)
		partTmp := re.ReplaceAllString(part, ".")
		formatParts = append(formatParts, partTmp)
	}
	log.Debug(formatParts)

	// 验证合法性
	// 1. query 串从解析顺序为 tag -> endpoint -> metric -> !, 否则返回 err
	// 2. query 数据中应该不超过 1 个 *

	err = validateTypeOrder(formatParts)
	if err != nil {
		return
	}

	err = validateDataStarValue(formatParts)
	if err != nil {
		return
	}

	return
}


func parseMultiTypeHelp(regexKey string) (tags []string, endpoints []string, metrics []string, additionItem APIAdditionItems, err error) {

	// query 的顺序必须为 tag -> endpoint -> metric -> !
	// 对于不想指定的属性，通过填写 * 来代表所有，如 tag##region=beijing3##*##downtime
	// 其中 * 代表所有的 endpoint，代表查询 tag 为 region=beijing3 的所有 endpoint 的 downtime 指标
	// todo 对于异常的 query 需要反馈给前端
	parts, formatErr:= formatInputHelp(regexKey)
	if formatErr != nil {
		err = formatErr
		return
	}

	// 对于一条 query，需要判断接下来返回的是控制层级还是数据层级，如果是控制层级，该返回哪个层级；如果是数据层级，返回哪个层级的数据
	// 需要两个参数：type，level （1/2/3/-1）
	// Type
	// 0: 控制层级
	// 1：数据层级

	// Level
	// 0:tag 层级
	// 1：endpoint 层级
	// 2：metric 层级
	// 3: ！(结束) 层级

	additionItem = APIAdditionItems{}
	for _, part := range parts {
		if additionItem.Type == 0 {
			switch part {
			case "tag":
				additionItem.Level = 0
			case "endpoint":
				additionItem.Level = 1
			case "metric":
				additionItem.Level = 2
			case "!":
				additionItem.Level = 3
				return
			}
			additionItem.Type = 1
		} else {
			switch additionItem.Level {
			case 0:
				if len(tags) > 0 && (part == "*" || tags[0] == "*"){
					err = fmt.Errorf("grafana query inputs error: tag contains *, can't be specific too")
					return
				}
				tags = append(tags, part)
			case 1:
				if len(endpoints) > 0 && (part == "*" || endpoints[0] == "*"){
					err = fmt.Errorf("grafana query inputs error: endpoint contains *, can't be specific")
					return
				}
				endpoints = append(endpoints, part)
			case 2:
				if len(metrics) > 0 && (part == "*" || metrics[0] == "*"){
					err = fmt.Errorf("grafana query inputs error: metric contains *, can't be specific")
					return
				}
				metrics = append(metrics, part)
			default:
				err = fmt.Errorf("grafana query inputs error: %s", regexKey)
				return
			}
			additionItem.Type = 0
		}
	}

	log.Debug(tags)
	log.Debug(endpoints)
	log.Debug(metrics)
	log.Debug(additionItem)
	return
}

func GrafanaMultiRender(c *gin.Context) {
	inputs := APIGrafanaRenderInput{}
	//set default step is 60
	inputs.Step = 60
	inputs.ConsolFun = "AVERAGE"
	if err := c.Bind(&inputs); err != nil {
		h.JSONR(c, badstatus, err.Error())
		return
	}
	respList := []*cmodel.GraphQueryResponse{}
	for _, target := range inputs.Target {

		tags, endpoints, metrics, _, parseErr := parseMultiTypeHelp(target)
		if parseErr != nil {
			log.Error(fmt.Sprintf("parse render query exception: %v", parseErr))
			continue
		}
		if len(metrics) == 0 {
			log.Error(fmt.Sprintf("render query should contain at least one metric"))
			continue
		}
		type CounterEnpRes struct {
			Counter		string
			Endpoint	string
		}
		var counterEnpRes []CounterEnpRes
		tagFilter := tagRelatedCounterFilter(tags)
		endpointFilter :=  endpointRelatedEndpointFilter(endpoints)
		metricFilter := metricRelatedCounterFilter(metrics)

		db.Graph.Table("endpoint_counter").Select("endpoint_counter.counter, endpoint.endpoint").
		Joins("join endpoint on endpoint_counter.endpoint_id = endpoint.id").
		Where(tagFilter).Where(endpointFilter).Where(metricFilter).Scan(&counterEnpRes)

		if len(counterEnpRes) == 0 {
			continue
		}

		for _, res := range counterEnpRes {
			resp, err := fetchData(res.Endpoint, res.Counter, inputs.ConsolFun, inputs.From, inputs.Until, inputs.Step)
			if err != nil {
				log.Debugf("query graph got error with: %v", inputs)
			} else {
				respList = append(respList, resp)
			}
		}
	}
	c.JSON(200, respList)
	return
}
