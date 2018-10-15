COMPILER:=	g++

RM:=				rm -rf

CPPFLAGS:=  -Isrc/includes/ \
            -std=c++11 \
            -Wl,-z,relro \
            -Wl,-z,defs \
            -Wl,-z,now \
            -Werror \
            -Wall \
            -Werror=implicit-function-declaration \
            -Werror=format-security \
            -g

SRCS:= 			src/main.cpp \
						src/app.cpp

OBJS:=			$(SRCS:.cpp=.o)

NAME:= 			app

all: 				$(NAME)

$(NAME): 		$(OBJS)
						$(COMPILER) -o $(NAME) $(OBJS)

clean:
						$(RM) $(OBJS)

fclean: 		clean
						$(RM) $(NAME)

re: 				fclean all

.PHONY: 		all re clean fclean
