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
	for {
		for _, user := range a.ListUsers() {
			//swap upload and download for users
			hash := user.Hash()
			sent, recv := user.ResetTraffic()
			timeUnix:=time.Now().Unix()
                        if sent > 10 {
                                //log.Error(sent)
                                user.SetIPLimit(5)
                                var iips string
                                ip := user.GetI()
                                if len(ip) > 4 {
                                        log.Error("current:" + ip)
                                        //s, err := a.db.Exec("UPDATE `user` SET `u`=`u`+?, `d`=`d`+?,  `t`=?, `ip`=? WHERE  SHA2( CONCAT(port,passwd), 224) =?;", recv, sent, timeUnix, ip, hash)
                                        err := a.db.QueryRow("SELECT `ip` FROM `user` WHERE  SHA2( CONCAT(port,passwd), 224) =? LIMIT 1;",hash).Scan(&iips)
                                        if err != nil {
                                                log.Error(common.NewError("failed to pull data from the database").Base(err))
                                                time.Sleep(a.updateDuration)
                                                continue
                                        }

                                        //var iips string
                                        //s.Scan(&iips)
                                        log.Error("getsqlip:" + iips)
                                        var lip = strings.Split(ip, ",")
                                        for i:= 0;i<len(lip);i++{
                                                if !strings.Contains(iips, lip[i]) {
                                                        iips = iips + lip[i] +" "
                                                }
                                        }
                                        log.Error("outputip:" + iips)
                                ss, err := a.db.Exec("UPDATE `user` SET `u`=`u`+?, `d`=`d`+?,  `t`=?, `ip`=? WHERE  SHA2( CONCAT(port,passwd), 224) =?;", recv, sent, timeUnix, iips, hash)
                                if err != nil {
                                        log.Error(common.NewError("failed to update data to user table").Base(err))
                                        continue
                                }

                                if r, err := ss.RowsAffected(); err != nil {
                                        if r == 0 {
                                                a.DelUser(hash)
                                        }
                                }
                                }
                        }
                }
                log.Error("---mysql updated---")


		//update memory
		rows, err := a.db.Query("SELECT SHA2( CONCAT(port,passwd), 224) ,transfer_enable,d,u,enable FROM user")
		if err != nil {
			log.Error(common.NewError("failed to pull data from the database").Base(err))
			time.Sleep(a.updateDuration)
			continue
		}
		for rows.Next() {
			var hash string
			var transfer_enable, d, u, enable int64
			err := rows.Scan(&hash, &transfer_enable, &d, &u, &enable)
			if err != nil {
				log.Error(common.NewError("failed to obtain data from the query result").Base(err))
				break
			}
			if d+u < transfer_enable && enable == 1 {
				a.AddUser(hash)
			} else {
				a.DelUser(hash)
			}
		}

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
