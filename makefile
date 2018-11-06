COMPILER=		gcc

RM=					rm -rf

CFLAGS=     -Isrc/includes/ \
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

CFLAGS+=		`pkg-config --cflags gtk+-3.0`

GTK_LDFLAGS=`pkg-config --libs gtk+-3.0`

SRCS= 			src/main.c \
						src/app.c \
						src/views.c \
						src/my_sniffer.c

OBJS=				$(SRCS:.c=.o)

NAME= 			network-analysis

all: 				$(NAME)

$(NAME): 		$(OBJS)
						$(COMPILER) $(CFLAGS) $(SRCS) -o $(NAME) $(GTK_LDFLAGS)

clean:
						$(RM) $(OBJS)

fclean: 		clean
						$(RM) $(NAME)

re: 				fclean all

.PHONY: 		all re clean fclean
