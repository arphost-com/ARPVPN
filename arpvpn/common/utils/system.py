import os
import shlex
from logging import debug, error, warning
from subprocess import PIPE, Popen, run
from typing import List


class CommandResult:
    """Represents the result of a command execution."""

    def __init__(self, code: int, output: str, err: str):
        self.code = code
        self.output = output
        self.err = err
        self.successful = (code < 1)


class Command:
    """
    Represents an interface to interact with a binary, executable file.
    """

    def __init__(self, cmd):
        self.cmd = cmd

    @staticmethod
    def _split_pipeline(cmd: str) -> List[List[str]]:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = ""

        segments: List[List[str]] = []
        current_segment: List[str] = []
        for token in lexer:
            if token == "|":
                if not current_segment:
                    raise ValueError("Invalid command pipeline")
                segments.append(current_segment)
                current_segment = []
                continue
            current_segment.append(token)

        if not current_segment:
            raise ValueError("Invalid command pipeline")
        segments.append(current_segment)
        return segments

    @staticmethod
    def _run_pipeline(command_pipeline: List[List[str]]) -> CommandResult:
        if len(command_pipeline) == 1:
            proc = run(command_pipeline[0], shell=False, check=False, stdout=PIPE, stderr=PIPE)
            return CommandResult(
                proc.returncode,
                proc.stdout.decode("utf-8", errors="replace").strip(),
                proc.stderr.decode("utf-8", errors="replace").strip(),
            )

        processes = []
        previous_proc = None
        for segment in command_pipeline:
            proc = Popen(
                segment,
                stdin=previous_proc.stdout if previous_proc else None,
                stdout=PIPE,
                stderr=PIPE,
            )
            if previous_proc and previous_proc.stdout:
                previous_proc.stdout.close()
            processes.append(proc)
            previous_proc = proc

        stdout, last_stderr = processes[-1].communicate()
        stderr_parts = []
        return_code = 0

        for index, proc in enumerate(processes):
            if index < len(processes) - 1:
                proc.wait()
                stderr_blob = proc.stderr.read() if proc.stderr else b""
            else:
                stderr_blob = last_stderr

            if proc.returncode != 0 and return_code == 0:
                return_code = proc.returncode

            stderr_text = stderr_blob.decode("utf-8", errors="replace").strip()
            if stderr_text:
                stderr_parts.append(stderr_text)

        return CommandResult(
            return_code,
            stdout.decode("utf-8", errors="replace").strip(),
            "\n".join(stderr_parts).strip(),
        )

    @staticmethod
    def _should_retry_without_sudo(err: str) -> bool:
        if not err:
            return False
        checks = (
            "you do not exist in the passwd database",
            "No such file or directory: 'sudo'",
            "sudo: not found",
        )
        return any(check in err for check in checks)

    def run(self, as_root: bool = False) -> CommandResult:
        """
        Execute the command and return information about the execution.
        :param as_root: Run the command as root (using sudo)
        :return: A CommandResult object containing information about how the execution went.
        """
        cmd = self.cmd
        if as_root:
            cmd = f"sudo {cmd}"
        debug(f"Running '{cmd}'...")

        try:
            command_pipeline = self._split_pipeline(cmd)
            result = self._run_pipeline(command_pipeline)
            if as_root and not result.successful and self._should_retry_without_sudo(result.err):
                warning(f"Unable to use sudo for '{self.cmd}', retrying without sudo.")
                result = self._run_pipeline(self._split_pipeline(self.cmd))
        except Exception as exc:
            result = CommandResult(1, "", str(exc))

        if not result.successful:
            error(f"Failed to run '{cmd}': err={result.err} | out={result.output} | code={result.code}")
        return result

    def run_as_root(self) -> CommandResult:
        return self.run(True)


def try_makedir(path: str):
    try:
        os.makedirs(path)
        debug(f"Created folder ({path})...")
    except FileExistsError:
        pass
    except Exception as e:
        error(f"Unable to create folder: {e}.")
        raise
