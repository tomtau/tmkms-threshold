package main

import (
	zmq "github.com/pebbe/zmq4"

	"fmt"
	"log"
	"time"
)

//  The listener receives all messages flowing through the proxy, on its
//  pipe. In CZMQ, the pipe is a pair of ZMQ_PAIR sockets that connects
//  attached child threads. In other languages your mileage may vary:

func listener_thread() {
	pipe, _ := zmq.NewSocket(zmq.PAIR)
	pipe.Bind("inproc://pipe")

	//  Print everything that arrives on pipe
	for {
		msg, err := pipe.RecvMessage(0)
		if err != nil {
			break //  Interrupted
		}
		fmt.Printf("%q\n", msg)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	go listener_thread()

	time.Sleep(100 * time.Millisecond)

	subscriber, err := zmq.NewSocket(zmq.XSUB)
	if err != nil {
		panic(err)
	}
	//err = subscriber.Connect("tcp://localhost:6000")
	err = subscriber.Bind("tcp://*:6000")
	if err != nil {
		panic(err)
	}

	publisher, err := zmq.NewSocket(zmq.XPUB)
	if err != nil {
		panic(err)
	}
	err = publisher.Bind("tcp://*:6001")
	if err != nil {
		panic(err)
	}

	listener, _ := zmq.NewSocket(zmq.PAIR)
	listener.Connect("inproc://pipe")

	err = zmq.Proxy(subscriber, publisher, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("interrupted")

}
