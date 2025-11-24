package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/p4gefau1t/trojan-go/config"

	// MySQL Driver
	_ "github.com/go-sql-driver/mysql"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
)

const Name = "MYSQL"
// connect db
type Authenticator struct {
	*memory.Authenticator
	db             *sql.DB
	updateDuration time.Duration
	ctx            context.Context
}

func (a *Authenticator) updater() {
    cfg := config.FromContext(a.ctx, Name).(*Config)
	for {
		for _, user := range a.ListUsers() {
			// swap upload and download for users
			hash := user.Hash()
			sent, recv := user.ResetTraffic()
			//timeUnix := time.Now().Unix()

			if sent > 10 {
				// 限制单用户最多 IP 数
				//user.SetIPLimit(5)
                                user.SetSpeedLimit(1024*cfg.MySQL.SpeedLimit, 0)
				// 只有用户当前有 IP 且配置中 upload_ip = true 才处理 IP 字段
				if user.GetIP() != 0 && cfg.MySQL.UploadIP {

					// 1. 先从数据库读出已有的 ip 字段（空格分隔）
					var oldIPStr string
					err := a.db.QueryRow(
						"SELECT `ip` FROM `user` WHERE SHA2(CONCAT(port,passwd), 224) = ? LIMIT 1",
						hash,
					).Scan(&oldIPStr)

					if err != nil {
						if err == sql.ErrNoRows {
							oldIPStr = ""
						} else {
							log.Error(common.NewError("failed to pull data from the database").Base(err))
							time.Sleep(a.updateDuration)
							continue
						}
					}

					// 2. 用 map 做集合，把旧 IP 放进去（避免重复）
					ipSet := make(map[string]struct{})
					if oldIPStr != "" {
						for _, v := range strings.Fields(oldIPStr) { // 按空白分割 "1.1.1.1 2.2.2.2"
							v = strings.TrimSpace(v)
							if v == "" {
								continue
							}
							ipSet[v] = struct{}{}
						}
					}

					// 3. 再把当前内存中的 IP 加进去（从 memory.User 拿 GetIPs）
					if mu, ok := user.(*memory.User); ok {
						newIPStr := mu.GetIPs() // 例如 "1.1.1.1,2.2.2.2"
						if newIPStr != "" {
							for _, v := range strings.Split(newIPStr, ",") {
								v = strings.TrimSpace(v)
								if v == "" {
									continue
								}
								ipSet[v] = struct{}{} // set 去重
							}
						}
					}

					// 4. 把集合里的 IP 拼成空格分隔字符串，准备写回 DB
					var b strings.Builder
					first := true
					for ip := range ipSet {
						if !first {
							b.WriteByte(' ')
						} else {
							first = false
						}
						b.WriteString(ip)
					}
					ipField := b.String()

					log.Warn("outputip: " + ipField)

					// 5. 更新数据库：u/d/t/ip
					ss, err := a.db.Exec(
						"UPDATE `user` SET `u`=`u`+?, `d`=`d`+?, `t`=UNIX_TIMESTAMP(), `ip`=? WHERE SHA2(CONCAT(port,passwd), 224) = ?",
						recv, sent, ipField, hash,
					)
					if err != nil {
						log.Error(common.NewError("failed to update data to user table").Base(err))
						continue
					}
					if r, err := ss.RowsAffected(); err == nil {
						if r == 0 {
							a.DelUser(hash)
						}
					} else {
						log.Error(common.NewError("failed to get RowsAffected").Base(err))
					}
				} else {
					// 没有 IP 或 upload_ip = false：只更新流量和时间，不动 ip 字段
					ss, err := a.db.Exec(
						"UPDATE `user` SET `u`=`u`+?, `d`=`d`+?, `t`=UNIX_TIMESTAMP() WHERE SHA2(CONCAT(port,passwd), 224) = ?",
						recv, sent, hash,
					)
					if err != nil {
						log.Error(common.NewError("failed to update data to user table").Base(err))
						continue
					}
					if r, err := ss.RowsAffected(); err == nil {
						if r == 0 {
							a.DelUser(hash)
						}
					} else {
						log.Error(common.NewError("failed to get RowsAffected").Base(err))
					}
				}
			}
		}

		log.Warn("---mysql updated---")

		// 同步内存中的用户列表（沿用你原来的逻辑）
		rows, err := a.db.Query("SELECT SHA2(CONCAT(port,passwd), 224), transfer_enable, d, u, enable FROM user")
		if err != nil {
			log.Error(common.NewError("failed to pull data from the database").Base(err))
			time.Sleep(a.updateDuration)
			continue
		}

		for rows.Next() {
			var hash string
			var transferEnable, d, u, enable int64
			err := rows.Scan(&hash, &transferEnable, &d, &u, &enable)
			if err != nil {
				log.Error(common.NewError("failed to obtain data from the query result").Base(err))
				break
			}
			if d+u < transferEnable && enable == 1 {
				a.AddUser(hash)
			} else {
				a.DelUser(hash)
			}
		}
                if err := rows.Err(); err != nil {
                        log.Error(common.NewError("row iteration error").Base(err))
                }
                rows.Close()
		select {
		case <-time.After(a.updateDuration):
		case <-a.ctx.Done():
			log.Debug("MySQL daemon exiting...")
			return
		}
	}
}

func connectDatabase(driverName, username, password, ip string, port int, dbName string) (*sql.DB, error) {
	path := strings.Join([]string{username, ":", password, "@tcp(", ip, ":", fmt.Sprintf("%d", port), ")/", dbName, "?charset=utf8"}, "")
	return sql.Open(driverName, path)
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	db, err := connectDatabase(
		"mysql",
		cfg.MySQL.Username,
		cfg.MySQL.Password,
		cfg.MySQL.ServerHost,
		cfg.MySQL.ServerPort,
		cfg.MySQL.Database,
	)
	if err != nil {
		return nil, common.NewError("Failed to connect to database server").Base(err)
	}
	memoryAuth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		db:             db,
		ctx:            ctx,
		updateDuration: time.Duration(cfg.MySQL.CheckRate) * time.Second,
		Authenticator:  memoryAuth.(*memory.Authenticator),
	}
	go a.updater()
	log.Debug("mysql authenticator created")
	return a, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
