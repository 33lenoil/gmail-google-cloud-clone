

SRC_DIR = .

SMTP_MAIN = ./smtpserver.cc

#HTTP_SRCS = $(filter-out $(SMTP_MAIN), $(shell find $(SRC_DIR) -type f -name '*.cc'))

HTTP_SRCS = utils.cc http-request.cc http-response.cc request-handler.cc backendMessage.cc email_utils.cc httpserver.cc smtpclient.cc

LB_SRCS = utils.cc http-request.cc http-response.cc request-handler.cc backendMessage.cc email_utils.cc smtpclient.cc loadbalancer.cc 

%.o: %.cc
	g++ $^ -c -o $@

httpserver: $(HTTP_SRCS)
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -lresolv -g -o $@

loadbalancer: $(LB_SRCS)
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -lresolv -g -o $@


smtpserver: smtpserver.cc smtpclient.cc backendMessage.cc email_utils.cc
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -lresolv -g -o $@

smtpclient: smtpclient.cc
	g++ $^ -lresolv -g -o $@


clean::
	rm -fv $(TARGETS) *~

TARGETS = backendCoordinator backendMessage backendWorker

all: $(TARGETS)

%.o: %.cc
	g++ $^ -c -o $@

backendMessage: backendMessage.o
	g++ backendMessage.cc -c -o backendMessage.o

backendCoordinator: backendMessage.o backendCoordinator.o
	g++ $^ -o $@ -lpthread -lstdc++fs -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto
	
backendWorker: backendMessage.o backendWorker.o
	g++ $^ -o $@ -g -lpthread -lstdc++fs -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto

pack:
	rm -f backend.zip
	zip -r backend.zip README Makefile *.c* *.h*

clean::
	rm -fv $(TARGETS) *~ *.o backend.zip

realclean:: clean
	rm -fv backend.zip
