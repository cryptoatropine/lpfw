all:
	g++ -g main.cpp -lnetfilter_queue -lpthread -o rewrite
