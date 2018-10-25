COMPILER:=	gcc

RM:=		rm -rf

CPPFLAGS:=  -Isrc/includes/ \
            -Wall \
            -Wextra \
            -Wundef \
            -Werror-implicit-function-declaration \
            -Wshadow \
            -Wpointer-arith \
            -Wcast-align \
            -Wstrict-prototypes \
            -Wunreachable-code \
            -Wconversion \
            -ftrapv

SRCS:= 	src/main.c \
		src/app.c

OBJS:=	$(SRCS:.c=.o)

NAME:= 	app

all: 		$(NAME)

$(NAME): 	$(OBJS)
		$(COMPILER) -o $(NAME) $(OBJS) -lncurses

clean:
		$(RM) $(OBJS)

fclean: 	clean
		$(RM) $(NAME)

re: 		fclean all

.PHONY: 	all re clean fclean
