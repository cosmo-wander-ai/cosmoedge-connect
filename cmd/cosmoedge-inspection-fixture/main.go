package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectionfixture"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "巡检测试命令执行失败："+err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("启动参数不完整")
	}
	defaultRoot, err := defaultStateRoot()
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "provision-token" {
		return runProvisionToken(args[1:], defaultRoot, output)
	}
	flags := flag.NewFlagSet("cosmoedge-inspection-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateRoot := flags.String("state-root", defaultRoot, "owner-only fixture state directory")
	assetSource := flags.String("asset-source", filepath.Join("internal", "inspectionfixture", "testdata", "assets"), "repository fixture asset directory")
	assetRoot := flags.String("asset-root", "", "owner-only runtime fixture asset directory")
	tokenFile := flags.String("token-file", "", "owner-only bearer token file")
	address := flags.String("listen", inspectionfixture.DefaultAddress, "loopback listen address")
	prepareOnly := flags.Bool("prepare-assets-only", false, "prepare protected realistic assets and exit")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("命令参数无效")
	}
	if *assetRoot == "" {
		*assetRoot = filepath.Join(*stateRoot, "assets")
	}
	if *tokenFile == "" {
		*tokenFile = filepath.Join(*stateRoot, "channel.token")
	}
	if err := inspectionfixture.PrepareAssetRoot(*assetSource, *assetRoot); err != nil {
		return fmt.Errorf("准备测试素材：%w", err)
	}
	if *prepareOnly {
		fmt.Fprintln(output, "真实感测试素材已准备完成。")
		return nil
	}
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: *stateRoot, AssetRoot: *assetRoot, TokenFile: *tokenFile, Address: *address,
	})
	if err != nil {
		return err
	}
	if err := service.Start(context.Background()); err != nil {
		return err
	}
	readiness := service.Readiness()
	if !readiness.Ready {
		_ = service.Stop()
		return errors.New("巡检测试服务未进入就绪状态")
	}
	fmt.Fprintf(output, "巡检测试服务已就绪，地址：%s\n", readiness.Address)
	select {
	case <-ctx.Done():
		return service.Stop()
	}
}

func runProvisionToken(args []string, defaultRoot string, output io.Writer) error {
	flags := flag.NewFlagSet("cosmoedge-inspection-fixture provision-token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateRoot := flags.String("state-root", defaultRoot, "owner-only fixture state directory")
	tokenFile := flags.String("token-file", "", "owner-only bearer token file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("令牌初始化参数无效")
	}
	if *tokenFile == "" {
		*tokenFile = filepath.Join(*stateRoot, "channel.token")
	}
	if err := inspectionfixture.ProvisionToken(*tokenFile); err != nil {
		return fmt.Errorf("初始化访问令牌：%w", err)
	}
	fmt.Fprintln(output, "巡检测试访问令牌已安全创建。")
	return nil
}

func defaultStateRoot() (string, error) {
	root, err := localstate.DefaultStateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "inspection-fixture"), nil
}
