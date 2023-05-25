package pdbot

import (
	"encoding/json"
	"fmt"
	"github.com/PagerDuty/go-pagerduty"
	"github.com/gin-gonic/gin"
	"github.com/go-lark/lark"
	"net/http"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"os"
	"time"
	"log"
)

type Server struct {
	// References
	PagerdutyClient *pagerduty.Client
	LarkBot         *lark.Bot

	// Database Tables
	EscalationPolicies map[string]*pagerduty.EscalationPolicy `json:"escalationPolicies"`
	Users              map[string]*pagerduty.User             `json:"users"`
	Schedules          map[string]*pagerduty.Schedule         `json:"schedules"`

	EmailToLarkUserIDs map[string]string `json:"emailToLarkUserIDs"`

	// Indices
	EscalationPoliciesIDByName map[string]string `json:"escalationPoliciesIDByName"`
}

func NewServer() *Server {
	var server Server

	pdAuthToken := os.Getenv("PAGERDUTY_AUTH_TOKEN")
	if pdAuthToken == "" {
		log.Panicln("Please set PAGERDUTY_AUTH_TOKEN env var")
	} else {
		server.PagerdutyClient = pagerduty.NewClient(pdAuthToken)
	}

	larkAppID := os.Getenv("LARK_APP_ID")
	larkAppSecret := os.Getenv("LARK_APP_SECRET")
	if larkAppSecret == "" {
		log.Panicln("Please set LARK_APP_ID env var")
	} else if larkAppSecret == "" {
		log.Panicln("Please set LARK_APP_SECRET env var")
	} else {
		server.LarkBot = lark.NewChatBot(larkAppID, larkAppSecret)
	}

	server.EscalationPolicies = make(map[string]*pagerduty.EscalationPolicy)
	server.Users = make(map[string]*pagerduty.User)
	server.Schedules = make(map[string]*pagerduty.Schedule)
	server.EscalationPoliciesIDByName = make(map[string]string)
	server.EmailToLarkUserIDs = make(map[string]string)
	return &server
}

func (this Server) Print() {
	b, _ := json.Marshal(this)
	fmt.Println(string(b))
}

func (this Server) LoadEscalationPolicies() {
	var opts pagerduty.ListEscalationPoliciesOptions
	opts.Limit = 100

	resp, err := this.PagerdutyClient.ListEscalationPolicies(opts)
	if err != nil {
		panic(err)
	}
	for _, obj := range resp.EscalationPolicies {
		var newObj pagerduty.EscalationPolicy
		newObj = obj
		this.EscalationPolicies[newObj.ID] = &newObj
		this.EscalationPoliciesIDByName[newObj.Name] = newObj.ID

	}
}

func (this Server) LoadUsers() {
	more := true
	var offset uint

	for more == true {
		var opts pagerduty.ListUsersOptions
		opts.Limit = 100
		opts.Offset = offset

		resp, err := this.PagerdutyClient.ListUsers(opts)
		if err != nil {
			panic(err)
		}
		for _, obj := range resp.Users {
			var newObj pagerduty.User
			newObj = obj
			this.Users[newObj.ID] = &newObj
		}
		more = resp.More
		offset += opts.Limit
	}

}

func (this Server) GetSchedule(scheduleID string) *pagerduty.Schedule {
	var opts pagerduty.GetScheduleOptions

	since := time.Now().Unix()
	until := time.Now().Unix() + 1

	sinceTime := time.Unix(since, 0)
	untilTime := time.Unix(until, 0)

	opts.TimeZone = "UTC"
	opts.Since = sinceTime.Format(time.RFC3339)
	opts.Until = untilTime.Format(time.RFC3339)

	schedule, err := this.PagerdutyClient.GetSchedule(scheduleID, opts)
	if err != nil {
		panic(err)
	}
	this.Schedules[schedule.ID] = schedule
	return schedule
}

func (this Server) PrintEscalationPolicyByName(rootMsgID string, escalationPolicyName string, buzz bool, larkMsg bool) string {
	escalationPolicyID, found := this.EscalationPoliciesIDByName[escalationPolicyName]
	if found {
		return this.PrintEscalationPolicy(rootMsgID, escalationPolicyID, buzz, larkMsg)
	} else {
		return ""
	}
}

func (this Server) PrintEscalationPolicy(rootMsgID string, escalationPolicyID string, buzz bool, larkMsg bool) string {
	var result string

	ep := this.EscalationPolicies[escalationPolicyID]

	result += fmt.Sprintf("=== [On-call users for \"%s\" (%s)] ===\n", ep.Name, ep.Description)

	cardColumnJSON := ""

	var oncallLarkUserIDs []string

	for i, escalationRule := range ep.EscalationRules {
		result += fmt.Sprintf("<Level %d>\n", i+1)

		oncallContent := ""

		for _, target := range escalationRule.Targets {
			if target.Type == "schedule_reference" {

				schedule := this.GetSchedule(target.ID)
				result += fmt.Sprintf("  - schedule(%s): ", schedule.Name)

				for _, scheduleOnCallUserObject := range schedule.FinalSchedule.RenderedScheduleEntries {
					scheduleOnCallUser, found := this.Users[scheduleOnCallUserObject.User.ID]
					if !found {
						result += fmt.Sprintf("(inactive) ")
						oncallContent += fmt.Sprintf("(inactive) ")
					} else {
						if larkMsg {
							larkUserID := this.EmailToLarkUserIDs[scheduleOnCallUser.Email]
							result += fmt.Sprintf("<at user_id=\"%s\">%s</at> ", larkUserID, scheduleOnCallUser.Summary)
							oncallContent += fmt.Sprintf("<at id=\\\"%s\\\"></at> ", larkUserID)
							oncallLarkUserIDs = append(oncallLarkUserIDs, larkUserID)
						} else {
							result += fmt.Sprintf("%s ", scheduleOnCallUser.Email)
						}
					}
				}
				result += "\n"
			} else {
				user, found := this.Users[target.ID]
				if !found {
					result += fmt.Sprintf("  - (inactive) ")
					oncallContent += fmt.Sprintf("(inactive) ")
				} else {
					if larkMsg {
						larkUserID := this.EmailToLarkUserIDs[user.Email]
						result += fmt.Sprintf("  - <at user_id=\"%s\">%s</at>\n", larkUserID, user.Summary)
						oncallContent += fmt.Sprintf("<at id=\\\"%s\\\"></at> ", larkUserID)
						oncallLarkUserIDs = append(oncallLarkUserIDs, larkUserID)
					} else {
						result += fmt.Sprintf("  - %s\n", user.Email)
					}
				}
			}
		}
		if i != 0 {
			cardColumnJSON += ","
		}
		cardColumnJSON += fmt.Sprintf(`
      {
        "tag": "div",
        "text": {
          "content": "** Level %d **",
          "tag": "lark_md"
        }
      },
      {
        "tag": "div",
        "text": {
          "content": "%s",
          "tag": "lark_md"
        }
      },
      {
        "tag": "div",
        "text": {
          "content": "*Escalates after %d minutes*",
          "tag": "lark_md"
        }
      },
      {
        "tag": "hr"
      }
    `, i+1, oncallContent, escalationRule.Delay)

		result += fmt.Sprintf("  > escalates after %d minutes\n", escalationRule.Delay)
	}

	str := fmt.Sprintf(`
    {
      "header": {
        "template": "orange",
        "title": {
          "tag": "plain_text",
          "i18n": {
            "zh_cn": "Pagerduty Escalation Policy: \"%s\" - %s",
            "en_us": "Pagerduty Escalation Policy: \"%s\" - %s"
          }
        }
      },
      "i18n_elements": {
        "zh_cn": [
          {
            "tag": "column_set",
            "flex_mode": "none",
            "background_style": "default",
            "columns": [
              {
                "tag": "column",
                "width": "weighted",
                "weight": 1,
                "vertical_align": "top",
                "elements": [
                  %s
                ]
              }
            ]
          },
          {
            "tag": "column_set",
            "flex_mode": "none",
            "background_style": "default",
            "columns": []
          },
          {
            "actions": [
              {
                "tag": "button",
                "text": {
                  "content": "添加进群",
                  "tag": "plain_text"
                },
                "type": "primary",
                "value": {
                  "key1": "value1"
                }
              },
              {
                "tag": "button",
                "text": {
                  "content": "加急",
                  "tag": "plain_text"
                },
                "type": "danger",
                "value": {
                  "key1": "value1"
                },
                "confirm": {
                  "title": {
                    "tag": "plain_text",
                    "content": "Confirmation"
                  },
                  "text": {
                    "tag": "plain_text",
                    "content": "Are you sure?"
                  }
                }
              },
              {
                "tag": "button",
                "text": {
                  "content": "Pagerduty High Urgency Call",
                  "tag": "plain_text"
                },
                "type": "danger",
                "value": {
                  "key1": "value1"
                },
                "confirm": {
                  "title": {
                    "tag": "plain_text",
                    "content": "Confirmation"
                  },
                  "text": {
                    "tag": "plain_text",
                    "content": "Are you sure?"
                  }
                }                
              }
            ],
            "tag": "action"
          },
          {
            "tag": "hr"
          },
          {
            "tag": "div",
            "text": {
              "content": "[View on Pagerduty](%s/escalation_policies#%s) | [Incident Handling Guideline](https://www.google.com)",
              "tag": "lark_md"
            }
          }
        ],
        "en_us": [
          {
            "tag": "column_set",
            "flex_mode": "none",
            "background_style": "default",
            "columns": [
              {
                "tag": "column",
                "width": "weighted",
                "weight": 1,
                "vertical_align": "top",
                "elements": [
                  %s
                ]
              }
            ]
          },
          {
            "tag": "column_set",
            "flex_mode": "none",
            "background_style": "default",
            "columns": []
          },
          {
            "actions": [
              {
                "tag": "button",
                "text": {
                  "content": "Add to this lark group",
                  "tag": "plain_text"
                },
                "type": "primary",
                "value": {
                  "key1": "value1"
                }
              },
              {
                "tag": "button",
                "text": {
                  "content": "Buzz",
                  "tag": "plain_text"
                },
                "type": "danger",
                "value": {
                  "key1": "value1"
                },
                "confirm": {
                  "title": {
                    "tag": "plain_text",
                    "content": "Confirmation"
                  },
                  "text": {
                    "tag": "plain_text",
                    "content": "Are you sure?"
                  }
                }
              },
              {
                "tag": "button",
                "text": {
                  "content": "Pagerduty High Urgency Call",
                  "tag": "plain_text"
                },
                "type": "danger",
                "value": {
                  "key1": "value1"
                },
                "confirm": {
                  "title": {
                    "tag": "plain_text",
                    "content": "Confirmation"
                  },
                  "text": {
                    "tag": "plain_text",
                    "content": "Are you sure?"
                  }
                }                
              }
            ],
            "tag": "action"
          },
          {
            "tag": "hr"
          },
          {
            "tag": "div",
            "text": {
              "content": "[View on Pagerduty](%s/escalation_policies#%s) | [Incident Handling Guideline](https://www.google.com)",
              "tag": "lark_md"
            }
          }
        ]
      }
    }
  `,
		ep.Name, ep.Description,
		ep.Name, ep.Description,
		cardColumnJSON, os.Getenv("PAGERDUTY_URL_PREFIX"), ep.ID,
		cardColumnJSON, os.Getenv("PAGERDUTY_URL_PREFIX"), ep.ID)

	fmt.Printf("%s\n", str)

	msg := lark.NewMsgBuffer(lark.MsgInteractive)
	larkEmail := os.Getenv("TEST_EMAIL")
	if larkEmail != "" {
		msg.BindEmail(larkEmail)
	}
	if rootMsgID != "" {
		msg.BindReply(rootMsgID)
	}
	om := msg.Card(str).Build()
	resp, err := this.LarkBot.PostMessage(om)
	fmt.Println("resp: %v\n", resp)
	if err != nil {
		panic(err)
	}

	this.buzz("", oncallLarkUserIDs)

	return result
}

func (this Server) buzz(messageId string, userIDs []string) {
	type BuzzUsersResponseData struct {
		// UserList []GetUserByEmailResponseDataUser `json:"user_list"`
	}
	type BuzzUsersResponse struct {
		lark.BaseResponse
		Data BuzzUsersResponseData `json:"data"`
	}

	var respData BuzzUsersResponse
	err := this.LarkBot.PatchAPIRequest(
		"",
		"/open-apis/im/v1/messages/"+messageId+"/urgent_phone?user_id_type=open_id",
		true,
		map[string]interface{}{
			"user_id_list": userIDs,
		},
		&respData,
	)
	fmt.Printf("%v\n", respData)
	if err != nil {
		panic(err)
	}
}

func (this Server) LoadLarkUsers() {
	// get keys of "this.Users" map as a slice
	userIDs := make([]string, len(this.Users))
	i := 0
	for k := range this.Users {
		userIDs[i] = k
		i++
	}

	var userIDChunks [][]string
	// Lark API only accept at most 50 emails as one chunk
	chunkSize := 50
	for i := 0; i < len(userIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(userIDs) {
			end = len(userIDs)
		}
		userIDChunks = append(userIDChunks, userIDs[i:end])
	}

	// for every check of 50 email addresses, make API call
	for _, userIDChunk := range userIDChunks {
		var emails []string
		for _, userID := range userIDChunk {
			emails = append(emails, this.Users[userID].Email)
		}

		type GetUserByEmailResponseDataUser struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
		}
		type GetUserByEmailResponseData struct {
			UserList []GetUserByEmailResponseDataUser `json:"user_list"`
		}
		type GetUserByEmailResponse struct {
			lark.BaseResponse
			Data GetUserByEmailResponseData `json:"data"`
		}

		var respData GetUserByEmailResponse
		err := this.LarkBot.PostAPIRequest(
			"",
			"/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id",
			true,
			map[string]interface{}{
				"emails": emails,
			},
			&respData,
		)
		if err != nil {
			panic(err)
		}
		for _, userObj := range respData.Data.UserList {
			this.EmailToLarkUserIDs[userObj.Email] = userObj.UserID
		}
	}
}

func (this Server) rootHandler() func(c *gin.Context) {
	return func(c *gin.Context) {
		type RequestBody struct {
			Encrypt string `json:"encrypt"`
		}
		var reqBody RequestBody
		err := c.ShouldBindJSON(&reqBody)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
		}

		fmt.Printf("encrypt: %s\n", reqBody.Encrypt)

		larkAppDecryptKey := os.Getenv("LARK_APP_DECRYPT_KEY")
		if larkAppDecryptKey == "" {
			log.Panicln("Please set LARK_APP_DECRYPT_KEY env var")
		}
		decrypted, err := this.decrypt(reqBody.Encrypt, os.Getenv("LARK_APP_DECRYPT_KEY"))
		if err != nil {
			panic(err)
		}
		fmt.Printf("decrypted: %s\n", decrypted)

		type DecryptedEventBodyHeader struct {
			EventID    string `json:"event_id"`
			Token      string `json:"token"`
			CreateTime string `json:"create_time"`
			EventType  string `json:"event_type"`
			TenantKey  string `json:"tenant_key"`
			AppID      string `json:"app_id"`
		}
		type DecryptedEventBodyEventMessageMentionID struct {
			OpenID  string `json:"open_id"`
			UnionID string `json:"union_id"`
			UserID  string `json:"user_id"`
		}
		type DecryptedEventBodyEventMessageMention struct {
			ID        DecryptedEventBodyEventMessageMentionID `json:"id"`
			Key       string                                  `json:"key"`
			Name      string                                  `json:"name"`
			TenantKey string                                  `json:"tenant_key`
		}
		type DecryptedEventBodyEventMessage struct {
			ChatID      string                                  `json:"chat_id"`
			ChatType    string                                  `json:"chat_type"`
			Content     string                                  `json:"content"`
			CreateTime  string                                  `json:"create_time"`
			Mentions    []DecryptedEventBodyEventMessageMention `json:"mentions"`
			MessageID   string                                  `json:"message_id"`
			MessageType string                                  `json:"message_type"`
		}
		type DecryptedEventBodyEvent struct {
			Message DecryptedEventBodyEventMessage `json:"message"`
		}
		type DecryptedBody struct {
			Schema string                   `json:"schema"`
			Header DecryptedEventBodyHeader `json:"header"`
			Event  DecryptedEventBodyEvent  `json:"event"`

			// fields for a "challenge"
			Challenge string `json:"challenge"`
			Token     string `json:"token"`
			Type      string `json:"type"`
		}
		var decryptedBody DecryptedBody
		err = json.Unmarshal([]byte(decrypted), &decryptedBody)

		if err != nil {
			panic(err)
		}

		if len(decryptedBody.Challenge) > 0 { // challenge found
			c.JSON(http.StatusOK, map[string]interface{}{
				"challenge": decryptedBody.Challenge,
			})
			return
		} else if len(decryptedBody.Event.Message.Content) > 0 {
			if decryptedBody.Schema == "2.0" {
				fmt.Println("TEXT: ", decryptedBody.Event.Message.Content)
				type MsgContent struct {
					Text string `json:"text"`
				}
				var msgContent MsgContent
				err := json.Unmarshal([]byte(decryptedBody.Event.Message.Content), &msgContent)
				if err == nil {
					rg := regexp.MustCompile("^.*/")
					fullCmd := rg.ReplaceAllString(msgContent.Text, "/")
					rg = regexp.MustCompile("^.*/")
					fmt.Println("fullCmd: ", fullCmd)

					indexOfFirstSpace := strings.Index(fullCmd, " ")
					fmt.Printf("indexOfFirstSpace=%d\n", indexOfFirstSpace)
					cmd := ""
					param := ""
					if indexOfFirstSpace >= 0 {
						cmd = fullCmd[:indexOfFirstSpace]
						param = fullCmd[indexOfFirstSpace+1:]
					} else {
						cmd = fullCmd
					}
					fmt.Printf("cmd:--%s--\n", cmd)
					fmt.Printf("param:--%s--\n", param)

					larkBotOpenID := os.Getenv("LARK_BOT_OPEN_ID")
					if larkBotOpenID == "" {
						log.Panicln("Please set LARK_BOT_OPEN_ID env var")
					}

					mentionedThisBot := false
					for _, mention := range decryptedBody.Event.Message.Mentions {
						if mention.ID.OpenID == larkBotOpenID { // mentioned this bot
							mentionedThisBot = true
							break

						}
					}

					if mentionedThisBot {
						if cmd == "/list" {
							this.list(decryptedBody.Event.Message.MessageID)
						} else if cmd == "/at" {
							this.PrintEscalationPolicyByName(decryptedBody.Event.Message.MessageID, param, false, true)
						} else if cmd == "/buzz" {
							this.PrintEscalationPolicyByName(decryptedBody.Event.Message.MessageID, param, true, true)
						}
					}
				}
			}
		}
		c.IndentedJSON(http.StatusOK, map[string]interface{}{})
	}
}

func (this Server) list(rootMsgID string) {
	s := "=== list of Escalation Policies ===\n"
	for _, escalationPolicy := range this.EscalationPolicies {
		s += fmt.Sprintf("%s\n", escalationPolicy.Name)
	}

	msg := lark.NewMsgBuffer(lark.MsgText)
	larkEmail := os.Getenv("TEST_EMAIL")
	if larkEmail != "" {
		msg.BindEmail(larkEmail)
	}
	if rootMsgID != "" {
		msg.BindReply(rootMsgID)
	}
	om := msg.Text(s).Build()
	resp, err := this.LarkBot.PostMessage(om)
	fmt.Println("resp: %v\n", resp)
	if err != nil {
		panic(err)
	}
}

func (this Server) at() func(c *gin.Context) {
	return func(c *gin.Context) {
		type EscalationPolicyParams struct {
			Name string `form:"name"`
		}
		var params EscalationPolicyParams
		err := c.ShouldBind(&params)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
		} else {
			type Response struct {
				Msg string `json:"msg"`
			}
			var response Response
			response.Msg = this.PrintEscalationPolicyByName("", params.Name, false, true)
			// this.sendLarkMsg(response.Msg)
			c.IndentedJSON(http.StatusOK, response)
		}
	}
}

func (this Server) decrypt(encrypt string, key string) (string, error) {
	buf, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", fmt.Errorf("base64StdEncode Error[%v]", err)
	}
	if len(buf) < aes.BlockSize {
		return "", errors.New("cipher  too short")
	}
	keyBs := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyBs[:sha256.Size])
	if err != nil {
		return "", fmt.Errorf("AESNewCipher Error[%v]", err)
	}
	iv := buf[:aes.BlockSize]
	buf = buf[aes.BlockSize:]
	// CBC mode always works in whole blocks.
	if len(buf)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)
	n := strings.Index(string(buf), "{")
	if n == -1 {
		n = 0
	}
	m := strings.LastIndex(string(buf), "}")
	if m == -1 {
		m = len(buf) - 1
	}
	return string(buf[n : m+1]), nil
}

func (this Server) sendLarkMsg(msg string) {
	larkEmail := os.Getenv("TEST_EMAIL")
	if larkEmail != "" {
		this.LarkBot.PostText(msg, lark.WithEmail(larkEmail))
	}
}

func (this Server) Run(hostAndPort string) {

	this.LoadEscalationPolicies()
	this.LoadUsers()

	this.Print()

	_, err := this.LarkBot.GetTenantAccessTokenInternal(true)
	if err != nil {
		panic(err)
	}

	this.LoadLarkUsers()
	this.Print()

	router := gin.Default()
	router.GET("/at", this.at())
	router.POST("/", this.rootHandler())
	if hostAndPort == "" {
		hostAndPort = ":8080"
	}
	router.Run(hostAndPort)
}
