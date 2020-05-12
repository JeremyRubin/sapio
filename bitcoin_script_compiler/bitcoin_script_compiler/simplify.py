import logging
from collections import defaultdict
from typing import DefaultDict, List, Tuple, Type, Union, cast, Literal

from .clause import (
    AbsoluteTimeSpec,
    AfterClause,
    CheckTemplateVerifyClause,
    DNFClause,
    RelativeTimeSpec,
    SatisfiedClause,
    TimeSpec,
    UnsatisfiableClause,
)
from .variable import AssignedVariable


class AfterClauseSimplification:
    """
    AfterClauseSimplification goes through a list of AfterClauses and reduces any
    CheckLockTimeVerify or CheckSequenceVerify lock times to at most two.
    It also sanity checks that the timeouts requested should either be relative
    or absolute but not both.

    It does not check that CTV is not used, which may externally conflict

    The ClassVar PRUNE_MODE can be configured to make incompatible timelocks an error,
    but the default behavior is to return an UnsatisfiableClause which results in a pruned
    DNF branch.
    """
    ReturnType = Union[
        UnsatisfiableClause,
        Tuple[Union[SatisfiedClause, AfterClause], Union[SatisfiedClause, AfterClause]],
    ]
    PRUNE_MODE: bool = True

    def simplify(self, clauses: List[AfterClause]) -> ReturnType:

        log = logging.getLogger("compiler").getChild(self.__class__.__name__)
        relative_or_absolute: DefaultDict[Type[TimeSpec], List[TimeSpec]] = defaultdict(
            list
        )
        ret: List[Union[SatisfiedClause, AfterClause]] = [
            SatisfiedClause(),
            SatisfiedClause(),
        ]
        for cl in clauses:
            assert cl.a.assigned_value is not None
            relative_or_absolute[type(cl.a.assigned_value)].append(cl.a.assigned_value)
        relative = relative_or_absolute[RelativeTimeSpec]
        absolute = relative_or_absolute[AbsoluteTimeSpec]
        relative_blocks_or_time: DefaultDict[Union[Literal["time"],
                                                   Literal["blocks"]],
                                             RelativeTimeSpec]= defaultdict(list)
        for cl2 in relative:
            relative_blocks_or_time[cl2.get_type()].append(cl2)
        relative_blocks = relative_blocks_or_time[RelativeTimeSpec.Blocks]
        relative_time = relative_blocks_or_time[RelativeTimeSpec.Time]
        if not (
            (len(relative_time) > 0) ^ (len(relative_blocks) > 0)
            or not (relative_blocks or relative_time)
        ):
            # Todo: Is this a true error? Or can we simply safely prune this branch...
            if self.PRUNE_MODE:
                log.warning("Incompatible Relative Time Locks! Pruning Branch")
                return UnsatisfiableClause()
            else:
                raise AssertionError("Incompatible Relative Time Locks in Branch")
        elif relative_blocks or relative_time:
            (_, tl) = max((tl.time, tl) for tl in relative_blocks + relative_time)
            ret[0] = AfterClause(AssignedVariable(tl, "relative_time_lock"))

        absolute_blocks_or_time: DefaultDict[Union[Literal["time"],
                                                   Literal["blocks"]],
                                             AbsoluteTimeSpec]= defaultdict(list)
        for cl3 in absolute:
            absolute_blocks_or_time[cl3.get_type()].append(cl3)
        absolute_blocks = absolute_blocks_or_time[AbsoluteTimeSpec.Blocks]
        absolute_time = absolute_blocks_or_time[AbsoluteTimeSpec.Time]
        if not (
            (len(absolute_time) > 0) ^ (len(absolute_blocks) > 0)
            or not (absolute_time or absolute_blocks)
        ):
            # Todo: Is this a true error? Or can we simply safely prune this branch...
            if self.PRUNE_MODE:
                log.warning("Incompatible Absolute Time Locks! Pruning Branch")
                return UnsatisfiableClause()
            else:
                raise AssertionError("Incompatible Absolute Time Locks in Branch")
        elif absolute_time or absolute_blocks:
            (_, tl) = max((tl.time, tl) for tl in absolute_blocks + absolute_time)
            ret[1] = AfterClause(AssignedVariable(tl, "absolute_time_lock"))
        return (ret[0], ret[1])


class DNFSimplification:
    """
    DNFSimplification goes through a List[DNFClause] and performs simplifications
    based on the type of a clause.

    Currently this is limited to AfterClause reduction and common CTV elimination.

    DNFSimplification can also detect and mark a List[DNFClause] as
    unsatisfiable if certain conflicts show up

    Future work can eliminate repeated public-keys, use MuSig keys, check for repeated
    pre-images, and other simplifiers.

    Cross-branch common clause aggregation must happen at a separate layer.
    """
    PRUNE_MODE: bool = True

    def simplify(self, all_clauses: List[DNFClause]) -> List[DNFClause]:
        clauses_to_return: List[DNFClause] = []
        log = logging.getLogger("compiler").getChild(self.__class__.__name__)
        clause_by_type = defaultdict(list)
        for cl in all_clauses:
            clause_by_type[type(cl)].append(cl)

        if AfterClause in clause_by_type:
            after_clauses = cast(List[AfterClause], clause_by_type.pop(AfterClause))
            val = AfterClauseSimplification().simplify(after_clauses)
            if isinstance(val, tuple):
                (a, b) = val
                if not isinstance(a, SatisfiedClause):
                    clauses_to_return.append(a)
                if not isinstance(b, SatisfiedClause):
                    clauses_to_return.append(b)
            else:
                return [UnsatisfiableClause()]
        if CheckTemplateVerifyClause in clause_by_type:
            ctv_clauses = cast(
                List[CheckTemplateVerifyClause],
                clause_by_type.pop(CheckTemplateVerifyClause),
            )
            if len(ctv_clauses) <= 1:
                clauses_to_return.extend(list(ctv_clauses))
            else:
                first = ctv_clauses[0].a.assigned_value
                if not all(clause.a.assigned_value == first for clause in ctv_clauses):
                    if self.PRUNE_MODE:
                        log.warning("Pruning Incompatible CheckTemplateVerify")
                        return [UnsatisfiableClause()]
                    else:
                        raise AssertionError("Incompatible CheckTemplateVerify Clause")
                else:
                    clauses_to_return.append(ctv_clauses[0])

        for (type_, clauses) in clause_by_type.items():
            clauses_to_return += clauses

        return clauses_to_return
