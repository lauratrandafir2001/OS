// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"
#include <fcntl.h>

#define READ 0
#define WRITE 1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	char *dirr = get_word(dir);

	int rp = chdir(dirr);

	if (rp != 0) {
		/* If chdir returns a non-zero value, an error occurred. */
		free(dirr);
		return false;
	}
	free(dirr);
	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	exit(0);
	/* TODO: Replace with actual exit code. */
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL)
		return 0;
	/* TODO: If builtin command, execute the command. */
	char *verb = get_word(s->verb);
	if (strcmp(verb, "cd") == 0) {
		if (s->out != NULL) {
			char *out = get_word(s->out);
			int fd;
			fd = open(out, O_CREAT, 0666);
			free(out);
		}
		if (shell_cd(s->params) == false) {
			printf("Error: Failed to change directory\n");
			free(verb);
			return -1;
		}
		free(verb);
		return 0;
	}
	if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0) {
		free(verb);
		shell_exit();
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL) {
		if (strcmp(s->verb->next_part->string, "=") == 0) {
			if (s->verb->next_part->next_part != NULL) {
				char *next_part = get_word(s->verb->next_part->next_part);

				int res = setenv(s->verb->string, next_part, 1);

				free(next_part);
				free(verb);
				return res;
			}
			free(verb);
			return 1;
		}
		free(verb);
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid == -1) {
		/* Failed to fork. */
		printf("faled to fork");
		free(verb);
		return -1;
	} else if (pid == 0) {
		/* Child process. */

		/* TODO: Perform redirections in child. */
		if (s->in != NULL) {
			char *in = get_word(s->in);
			int fd = open(in, O_RDONLY, 0666);
			free(in);
			if (fd == -1) {
				printf("Error: Failed to open input file %s\n", in);
				exit(1);
			}
			dup2(fd, STDIN_FILENO);
			close(fd);
		} 
		if (s->err != NULL) {
			int fd;
			char *err = get_word(s->err);

			if (s->io_flags == IO_ERR_APPEND)
				fd = open(err, O_WRONLY | O_CREAT | O_APPEND, 0666);
			else
				fd = open(err, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);
			free(err);
			if (fd == -1)
			{
				printf("Error: Failed to open error file %s\n", err);
				free(verb);
				exit(1);
			}
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		if (s->out != NULL) {
			int fd;
			char *out = get_word(s->out);

			if (s->io_flags == IO_OUT_APPEND)
				fd = open(out, O_WRONLY | O_CREAT | O_APPEND, 0666);
			else
				fd = open(out, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);
			if (fd == -1)
			{
				printf("Error: Failed to open output file %s\n", out);
				free(out);
				free(verb);
				exit(1);
			}
			free(out);
			dup2(fd, STDOUT_FILENO);
			close(fd);
		}

		int size;
		char **argv = get_argv(s, &size);

		if (execvp(verb, argv) == -1)
		{
			printf("Execution failed for '%s'\n", verb);
			free(verb);
			free(argv);
			exit(EXIT_FAILURE);
		}
		free(verb);
		free(argv);
	} else
	{
		/* Parent process. */
		int status;
		waitpid(pid, &status, 0);
		/* TODO: Replace with actual exit status. */
		free(verb);
		return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;

	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1 = fork();
	if (pid1 == -1) {
		/* Failed to fork. */
		printf("faled to fork");
		return -1;
	}
	if (pid1 == 0) {
		/* Child process. */
		int ret = parse_command(cmd1, level, father);

		exit(ret);
	}
	pid_t pid2 = fork();
	if (pid2 == -1) {
		/* Failed to fork. */
		printf("faled to fork");
		return -1;
	} else if (pid2 == 0) {
		/* Child process. */
		int ret = parse_command(cmd2, level, father);

		exit(ret);
	}
	int status;

	waitpid(pid1, &status, 0);
	waitpid(pid2, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int fd[2];
	pipe(fd);
	pid_t pid1 = fork();

	if (pid1 == -1) {
		/* Failed to fork. */
		printf("faled to fork");
		return -1;
	}
	if (pid1 == 0) {
		/* Child process. */
		close(fd[READ]);
		dup2(fd[WRITE], STDOUT_FILENO);
		int ret = parse_command(cmd1, level, father);
		close(fd[WRITE]);
		exit(ret);
	}
	pid_t pid2 = fork();

	if (pid2 == -1) {
		/* Failed to fork. */
		printf("faled to fork");
		return -1;
	} else if (pid2 == 0) {
		/* Child process. */
		close(fd[WRITE]);
		dup2(fd[READ], STDIN_FILENO);
		int ret = parse_command(cmd2, level, father);
		close(fd[READ]);
		exit(ret);
	}
	/* Parent process. */
	int status;

	waitpid(pid1, &status, 0);
	close(fd[WRITE]);
	waitpid(pid2, &status, 0);
	close(fd[READ]);
	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */

	if (c->op == OP_NONE)
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, father);

	switch (c->op)
	{
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		parse_command(c->cmd1, level, father);
		return parse_command(c->cmd2, level, father);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level, father) != 0)
			return parse_command(c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level, father) == 0)
			return parse_command(c->cmd2, level, father);
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO: Replace with actual exit code of command. */
}
