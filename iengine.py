import sys
from itertools import product
import re

def parse_file(filename):
    with open(filename, 'r') as file:
        content = file.read().split("ASK")
        tell = content[0].strip().split("TELL")[1].strip()
        ask = content[1].strip()
        clauses = [clause.strip() for clause in tell.split(";") if clause.strip()]
        return clauses, ask

def evaluate(clause, assignment):
    tokens = re.findall(r'\w+|<=>|=>|&|\||\|\||!|~', clause)
    stack = []
    precedence = {'~': 4, '!': 4, '&': 3, '||': 2, '|': 2, '=>': 1, '<=>': 0}
    op_stack = []

    def apply_operator(op, right, left=None):
        if op in ('!', '~'):
            return not right
        elif op == '&':
            return left and right
        elif op in ('|', '||'):
            return left or right
        elif op == '=>':
            return not left or right
        elif op == '<=>':
            return left == right

    for token in tokens:
        if token.isalnum():
            stack.append(assignment.get(token, False))
        elif token in precedence:
            while (op_stack and precedence[op_stack[-1]] >= precedence[token]):
                operator = op_stack.pop()
                right = stack.pop()
                left = stack.pop() if stack and operator not in ('!', '~') else None
                stack.append(apply_operator(operator, right, left))
            op_stack.append(token)
        else:
            raise ValueError("Invalid token")

    while op_stack:
        operator = op_stack.pop()
        right = stack.pop()
        left = stack.pop() if stack and operator not in ('!', '~') else None
        stack.append(apply_operator(operator, right, left))

    return stack[0]

def truth_table_check(kb, query):
    symbols = {symbol for clause in kb for symbol in re.findall(r'\w+', clause)}
    models = 0
    entailed = False

    for values in product([False, True], repeat=len(symbols)):
        assignment = dict(zip(symbols, values))
        if all(evaluate(clause, assignment) for clause in kb):
            models += 1
            if evaluate(query, assignment):
                entailed = True

    return "YES" if entailed else "NO", models

def forward_chaining(kb, query):
    inferred = set()
    agenda = {clause for clause in kb if "=>" not in clause and "<=>" not in clause}
    inferred.update(agenda)
    agenda_list = list(agenda)  

    activated = True
    while activated:
        activated = False
        for clause in kb:
            if "=>" in clause:
                premises, conclusion = map(str.strip, clause.split("=>"))
                premises = [prem.strip() for prem in premises.split("&")]
                if conclusion not in inferred:
                    if all(prem in inferred for prem in premises):
                        inferred.add(conclusion)
                        agenda_list.append(conclusion)
                        activated = True
                        if conclusion == query:
                            break

    return "YES" if query in inferred else "NO", agenda_list

def backward_chaining(kb, query):
    inferred = set()
    facts = {clause for clause in kb if "=>" not in clause and "<=>" not in clause}
    chain = []

    def bc_ask(q):
        if q in facts:
            if q not in chain:
                chain.append(q)
            return True
        if q in inferred:
            return True
        inferred.add(q)
        for rule in kb:
            if "=>" in rule:
                premises, conclusion = map(str.strip, rule.split("=>"))
                if conclusion == q:
                    premises = premises.split("&")
                    if all(bc_ask(prem.strip()) for prem in premises):
                        if q not in chain:
                            chain.extend([prem.strip() for prem in premises if prem.strip() not in chain])
                            chain.append(q)
                        return True
            elif "<=>" in rule:
                left, right = map(str.strip, rule.split("<=>"))
                if (left == q and bc_ask(right)) or (right == q and bc_ask(left)):
                    if q not in chain:
                        chain.append(right if left == q else left)
                        chain.append(q)
                    return True
        return False

    result = bc_ask(query)
    return "YES" if result else "NO", chain

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python iengine.py <filename> <method>")
        sys.exit(1)

    filename, method = sys.argv[1], sys.argv[2].upper()
    kb, query = parse_file(filename)

    if method == "TT":
        result, count = truth_table_check(kb, query)
        print(f"{result}: {count}")
    elif method == "FC":
        result, entailed = forward_chaining(kb, query)
        print(f"{result}: {', '.join(entailed)}")
    elif method == "BC":
        result, entailed = backward_chaining(kb, query)
        print(f"{result}: {', '.join(entailed)}")
    else:
        print("Invalid method. Choose TT, FC, or BC.")
