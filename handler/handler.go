package handler

import (
	// "fmt"
	"github.com/sirupsen/logrus"
	"free5gc/lib/openapi/models"
	"free5gc/src/ausf/handler/message"
	"free5gc/src/ausf/producer"
	"free5gc/src/ausf/logger"
	"time"
)

const (
	MaxChannel int = 20
)

var ausfChannel chan message.HandlerMessage
var HandlerLog *logrus.Entry

func init() {
	HandlerLog = logger.HandlerLog
	ausfChannel = make(chan message.HandlerMessage, MaxChannel)
}

func SendMessage(msg message.HandlerMessage) {
	ausfChannel <- msg
}

func Handle() {
	for {
		select {
		case msg, ok := <-ausfChannel:
			if ok {
				switch msg.Event {
				case message.EventUeAuthPost:
					producer.HandleUeAuthPostRequest(msg.ResponseChan, msg.HTTPRequest.Body.(models.AuthenticationInfo))
				case message.EventAuth5gAkaComfirm:
					authCtxId := msg.HTTPRequest.Params["authCtxId"]
					producer.HandleAuth5gAkaComfirmRequest(msg.ResponseChan, authCtxId, msg.HTTPRequest.Body.(models.ConfirmationData))
				case message.EventEapAuthComfirm:
					authCtxId := msg.HTTPRequest.Params["authCtxId"]
					producer.HandleEapAuthComfirmRequest(msg.ResponseChan, authCtxId, msg.HTTPRequest.Body.(models.EapSession))
				default:
					HandlerLog.Warnf("AUSF Event[%d] has not implemented", msg.Event)
				}
			} else {
				HandlerLog.Errorln("AUSF Channel closed!")
			}

		case <-time.After(time.Second * 1):

		}
	}
}
