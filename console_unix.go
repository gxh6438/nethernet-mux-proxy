//go:build !windows

package main

func platformInit() {}

// waitExit Unix：无终端场景（systemd 等）不能阻塞等待，直接返回。
func waitExit() {}
