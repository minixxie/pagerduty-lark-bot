package main

import (
  "fmt"
  "encoding/json"
  "time"
  "net/http"
  "github.com/PagerDuty/go-pagerduty"
  "github.com/go-lark/lark"
  "github.com/gin-gonic/gin"
)

var pagerdutyAuthToken = ""

type InMemoryDB struct {
  EscalationPolicies map[string]*pagerduty.EscalationPolicy  `json:"escalationPolicies"`
  Users map[string]*pagerduty.User   `json:"users"`
  Schedules map[string]*pagerduty.Schedule  `json:"schedules"`

  EmailToLarkUserIDs map[string]string  `json:"emailToLarkUserIDs"`

  // Indices
  EscalationPoliciesIDByName map[string]string  `json:"escalationPoliciesIDByName"`
}

func NewInMemoryDB() *InMemoryDB {
  var db InMemoryDB
  db.EscalationPolicies = make(map[string]*pagerduty.EscalationPolicy)
  db.Users = make(map[string]*pagerduty.User)
  db.Schedules = make(map[string]*pagerduty.Schedule)
  db.EscalationPoliciesIDByName = make(map[string]string)
  db.EmailToLarkUserIDs = make(map[string]string)
  return &db
}

func (this InMemoryDB) Print() {
  b, _ := json.Marshal(this)
  fmt.Println(string(b))
}

func (this InMemoryDB) LoadEscalationPolicies(pagerdutyClient *pagerduty.Client) {
  var opts pagerduty.ListEscalationPoliciesOptions
  opts.Limit = 100

  resp, err := pagerdutyClient.ListEscalationPolicies(opts)
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

func (this InMemoryDB) LoadUsers(pagerdutyClient *pagerduty.Client) {
  more := true
  var offset uint

  for more == true {
    var opts pagerduty.ListUsersOptions
    opts.Limit = 100
    opts.Offset = offset

    resp, err := pagerdutyClient.ListUsers(opts)
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

func (this InMemoryDB) GetSchedule(pagerdutyClient *pagerduty.Client, scheduleID string) *pagerduty.Schedule {
  var opts pagerduty.GetScheduleOptions

  since := time.Now().Unix()
  until := time.Now().Unix() + 1

  sinceTime := time.Unix(since, 0)
  untilTime := time.Unix(until, 0)

  opts.TimeZone = "UTC"
  opts.Since = sinceTime.Format(time.RFC3339)
  opts.Until = untilTime.Format(time.RFC3339)

  schedule, err := pagerdutyClient.GetSchedule(scheduleID, opts)
  if err != nil {
    panic(err)
  }
  this.Schedules[schedule.ID] = schedule
  return schedule
}

func (this InMemoryDB) PrintEscalationPolicyByName(pagerdutyClient *pagerduty.Client, escalationPolicyName string, larkMsg bool) string {
  escalationPolicyID, found := this.EscalationPoliciesIDByName[escalationPolicyName]
  if found {
    return this.PrintEscalationPolicy(pagerdutyClient, escalationPolicyID, larkMsg)
  } else {
    return ""
  }
}

func (this InMemoryDB) PrintEscalationPolicy(pagerdutyClient *pagerduty.Client, escalationPolicyID string, larkMsg bool) string {
  var result string

  ep := this.EscalationPolicies[escalationPolicyID]

  result += fmt.Sprintf("=== [On-call users for \"%s\" (%s)] ===\n", ep.Name, ep.Description)

  for i, escalationRule := range ep.EscalationRules {
    result += fmt.Sprintf("<Level %d>\n", i+1)

    for _, target := range escalationRule.Targets {
      if target.Type == "schedule_reference" {

        schedule := this.GetSchedule(pagerdutyClient, target.ID)
        result += fmt.Sprintf("  - schedule(%s): ", schedule.Name)

        for _, scheduleOnCallUserObject := range schedule.FinalSchedule.RenderedScheduleEntries {
          scheduleOnCallUser, found := this.Users[scheduleOnCallUserObject.User.ID]
          if !found {
            result += fmt.Sprintf("(inactive) ")
          } else {
            if larkMsg {
              larkUserID := this.EmailToLarkUserIDs[scheduleOnCallUser.Email]
              result += fmt.Sprintf("<at user_id=\"%s\">%s</at> ", larkUserID, scheduleOnCallUser.Summary)
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
        } else {
          if larkMsg {
            larkUserID := this.EmailToLarkUserIDs[user.Email]
            result += fmt.Sprintf("  - <at user_id=\"%s\">%s</at>\n", larkUserID, user.Summary)
          } else {
            result += fmt.Sprintf("  - %s\n", user.Email)
          }
        }
      }
    }
    result += fmt.Sprintf("  > escalates after %d minutes\n", escalationRule.Delay)
  }
  return result
}

func (this InMemoryDB) LoadLarkUsers(bot *lark.Bot) {
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
      UserID string  `json:"user_id"`
      Email string   `json:"email"`
    }
    type GetUserByEmailResponseData struct {
      UserList []GetUserByEmailResponseDataUser  `json:"user_list"`
    }
    type GetUserByEmailResponse struct {
      lark.BaseResponse
      Data GetUserByEmailResponseData `json:"data"`
    }

    var respData GetUserByEmailResponse
    err := bot.PostAPIRequest(
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

func at(inMemoryDB *InMemoryDB, pagerdutyClient *pagerduty.Client) func(c *gin.Context) {
  return func(c *gin.Context) {
    type EscalationPolicyParams struct {
      Name string  `form:"name"`
    }
    var params EscalationPolicyParams
    err := c.ShouldBind(&params)
    if err != nil {
      c.AbortWithStatus(http.StatusBadRequest)
    } else {
      type Response struct {
        Msg string  `json:"msg"`
      }
      var response Response
      response.Msg = inMemoryDB.PrintEscalationPolicyByName(pagerdutyClient, params.Name, true)
      sendLarkMsg(response.Msg)
      c.IndentedJSON(http.StatusOK, response)
    }
  }
}

var bot *lark.Bot

func sendLarkMsg(msg string) {
  bot.PostText(msg, lark.WithEmail("xxx@abc.com"))
}

func main() {
  inMemoryDB := NewInMemoryDB()
  pagerdutyClient := pagerduty.NewClient(pagerdutyAuthToken)

  inMemoryDB.LoadEscalationPolicies(pagerdutyClient)
  inMemoryDB.LoadUsers(pagerdutyClient)

  inMemoryDB.Print()

  appID := ""
  appSecret := ""
  bot = lark.NewChatBot(appID, appSecret)
  _, err := bot.GetTenantAccessTokenInternal(true)
  if err != nil {
    panic(err)
  }

  inMemoryDB.LoadLarkUsers(bot)
  inMemoryDB.Print()

  router := gin.Default()
  router.GET("/at", at(inMemoryDB, pagerdutyClient))
  router.Run("localhost:8080")
}
