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

package cron

import (
	"encoding/json"
	"fmt"
	"time"
	"sort"
	log "github.com/Sirupsen/logrus"

	cmodel "github.com/open-falcon/falcon-plus/common/model"
	"github.com/open-falcon/falcon-plus/modules/alarm/api"
	"github.com/open-falcon/falcon-plus/modules/alarm/g"
	"github.com/open-falcon/falcon-plus/modules/alarm/redi"
)

func consumeAll(event *cmodel.Event) {
	actionId := event.ActionId()
	if actionId <= 0 {
		return
	}

	action := api.GetAction(actionId)
	if action == nil {
		return
	}

	if action.Callback == 1 {
		HandleCallback(event, action)
	}
	consumeAllEvents(event, action)
}

func consumeAllEvents(event *cmodel.Event, action *api.Action) {
	if action.Uic == "" {
		return
	}

	phones, _, ims := api.ParseTeams(action.Uic)

	smsContent := GenerateSmsContent(event)
	//mailContent := GenerateMailContent(event)
	imContent := GenerateIMContent(event)

	// <=P2 才发送短信
	if event.Priority() < 3 {
		redi.WriteSms(phones, smsContent)
	}

	redi.WriteIM(ims, imContent)
	ParseUserAllMail(event, action)

}

func ParseUserAllMail(event *cmodel.Event, action *api.Action) {
	userMap := api.GetUsers(action.Uic)

	metric := event.Metric()
	subject := GenerateSmsContent(event)
	content := GenerateMailContent(event)
	status := event.Status
	priority := event.Priority()

	queue := g.Config().Redis.UserMailQueue

	rc := g.RedisConnPool.Get()
	defer rc.Close()

	_, mails, _ := api.ParseTeams(action.Uic)
	smsContent := GenerateSmsContent(event)
	mailContent := GenerateMailContent(event)

	for _, user := range userMap {
		dto := MailDto{
			Priority: priority,
			Metric:   metric,
			Subject:  subject,
			Content:  content,
			Email:    user.Email,
			Status:   status,
		}
		key := fmt.Sprintf("%d%s%s%s", dto.Priority, dto.Status, dto.Email, dto.Metric)

		if _, ok := KeyToTimestampMap[key]; ok {
			now := time.Now()
			history := KeyToTimestampMap[key]
			sort.Sort(history)
			log.Infof("history: %v", history)
			keyNum := getKeyNum(history, now)
			log.Infof("key num: %v", keyNum)

			if keyNum < 4 {
				// direct write mail
				redi.WriteMail(mails, smsContent, mailContent)
			} else{
				// go combine
				bs, err := json.Marshal(dto)
				if err != nil {
					log.Error("json marshal MailDto fail:", err)
					continue
				}

				_, err = rc.Do("LPUSH", queue, string(bs))
				if err != nil {
					log.Error("LPUSH redis", queue, "fail:", err, "dto:", string(bs))
				}
			}
			history = append(history, now)
			sort.Sort(history)
			KeyToTimestampMap[key] = history[1:]

		} else {
			initTime := time.Now().AddDate(-1, 0, 0)
			initHistory := History{initTime, initTime, initTime}
			KeyToTimestampMap[key] = initHistory
		}

	}
}


func getKeyNum(history History, now time.Time) int {
	if now.Sub(history[2]) > time.Minute * 5 {
		return 1
	} else if history[2].Sub(history[1]) > time.Minute * 5 {
		return 2
	} else if history[1].Sub(history[0]) > time.Minute * 5 {
		return 3
	} else {
		return 4
	}
}


func consume(event *cmodel.Event, isHigh bool) {
	actionId := event.ActionId()
	if actionId <= 0 {
		return
	}

	action := api.GetAction(actionId)
	if action == nil {
		return
	}

	if action.Callback == 1 {
		HandleCallback(event, action)
	}

	if isHigh {
		consumeHighEvents(event, action)
	} else {
		consumeLowEvents(event, action)
	}
}

// 高优先级的不做报警合并
func consumeHighEvents(event *cmodel.Event, action *api.Action) {
	if action.Uic == "" {
		return
	}

	phones, mails, ims := api.ParseTeams(action.Uic)

	smsContent := GenerateSmsContent(event)
	mailContent := GenerateMailContent(event)
	imContent := GenerateIMContent(event)

	// <=P2 才发送短信
	if event.Priority() < 3 {
		redi.WriteSms(phones, smsContent)
	}

	redi.WriteIM(ims, imContent)
	redi.WriteMail(mails, smsContent, mailContent)

}

// 低优先级的做报警合并
func consumeLowEvents(event *cmodel.Event, action *api.Action) {
	if action.Uic == "" {
		return
	}

	// <=P2 才发送短信
	if event.Priority() < 3 {
		ParseUserSms(event, action)
	}

	ParseUserIm(event, action)
	ParseUserMail(event, action)
}

func ParseUserSms(event *cmodel.Event, action *api.Action) {
	userMap := api.GetUsers(action.Uic)

	content := GenerateSmsContent(event)
	metric := event.Metric()
	status := event.Status
	priority := event.Priority()

	queue := g.Config().Redis.UserSmsQueue

	rc := g.RedisConnPool.Get()
	defer rc.Close()

	for _, user := range userMap {
		dto := SmsDto{
			Priority: priority,
			Metric:   metric,
			Content:  content,
			Phone:    user.Phone,
			Status:   status,
		}
		bs, err := json.Marshal(dto)
		if err != nil {
			log.Error("json marshal SmsDto fail:", err)
			continue
		}

		_, err = rc.Do("LPUSH", queue, string(bs))
		if err != nil {
			log.Error("LPUSH redis", queue, "fail:", err, "dto:", string(bs))
		}
	}
}

func ParseUserMail(event *cmodel.Event, action *api.Action) {
	userMap := api.GetUsers(action.Uic)

	metric := event.Metric()
	subject := GenerateSmsContent(event)
	content := GenerateMailContent(event)
	status := event.Status
	priority := event.Priority()

	queue := g.Config().Redis.UserMailQueue

	rc := g.RedisConnPool.Get()
	defer rc.Close()

	for _, user := range userMap {
		dto := MailDto{
			Priority: priority,
			Metric:   metric,
			Subject:  subject,
			Content:  content,
			Email:    user.Email,
			Status:   status,
		}
		bs, err := json.Marshal(dto)
		if err != nil {
			log.Error("json marshal MailDto fail:", err)
			continue
		}

		_, err = rc.Do("LPUSH", queue, string(bs))
		if err != nil {
			log.Error("LPUSH redis", queue, "fail:", err, "dto:", string(bs))
		}
	}
}

func ParseUserIm(event *cmodel.Event, action *api.Action) {
	userMap := api.GetUsers(action.Uic)

	content := GenerateIMContent(event)
	metric := event.Metric()
	status := event.Status
	priority := event.Priority()

	queue := g.Config().Redis.UserIMQueue

	rc := g.RedisConnPool.Get()
	defer rc.Close()

	for _, user := range userMap {
		dto := ImDto{
			Priority: priority,
			Metric:   metric,
			Content:  content,
			IM:       user.IM,
			Status:   status,
		}
		bs, err := json.Marshal(dto)
		if err != nil {
			log.Error("json marshal ImDto fail:", err)
			continue
		}

		_, err = rc.Do("LPUSH", queue, string(bs))
		if err != nil {
			log.Error("LPUSH redis", queue, "fail:", err, "dto:", string(bs))
		}
	}
}
