import angr
import sys

import logging as l


class Check:
    def __init__(self, target, arch, addr, value):
        self.target = target
        self.arch = arch
        self.addr = addr
        self.value = value

    def load_bin(self):
        p = angr.Project(self.target, load_options={'auto_load_libs': False})
        cfg = p.analyses.CFG()
        if self.arch == "x86_64":
            self.find_ddg_64(p)
            return
        elif self.arch == "x86":
            self.find_ddg_32(p)
            return
        else:
            logging.error("Unknown architecture specified")
            sys.exit()

    def find_ddg_32(self, proj):
        state = proj.factory.blank_state(addr=self.addr, add_options=angr.options.unicorn)
        state.options['ZERO_FILL_UNCONSTRAINED_MEMORY'] = False
        block = state.block()
        inst = block.capstone.insns[0]
        register_type = inst.insn.operands[0]
        proj.analyses.LoopFinder(normalize=True)
        register = inst.insn.reg_name(register_type.reg)
        state = proj.factory.full_init_state(addr=self.addr + size, add_options=angr.options.unicorn)
        setattr(state.regs, register, state.solver.BVS('a', 32))
        self.value = getattr(state.regs, register)
        if self.value != proj.arch.bits:
            self.value = self.value.zero_extend(proj.arch.bits - self.value.length)
        state.inspect.b('instruction', when=angr.BP_AFTER, action=self.explore_compare)
        sim = proj.factory.simulation_manager(state)
        sim.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
        sim.explore(find=self.explore_compare, n=100)
        ret = len(sim.found) > 0
        if ret is True:
            print("Found dependency of the destination register on future compare")
            return
        else:
            state.inspect.b('call', when=angr.BP_AFTER, action=self.explore_call)
            sim = proj.factory.simulation_manager(state)
            sim.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
            sim.explore(find=self.explore_call, n=100)
            ret = len(sim.found) > 0
            if ret is True:
                print("Found a dependency on destination register on future call")
                return

        print("found no dependencies for the destination register at the given instruction")
        return

    def find_ddg_64(self, proj):
        state = proj.factory.blank_state(addr=self.addr, add_options=angr.options.unicorn)
        state.options['ZERO_FILL_UNCONSTRAINED_MEMORY'] = False
        block = state.block()
        inst = block.capstone.insns[0]
        register_type = inst.insn.operands[0]
        proj.analyses.LoopFinder(normalize=True)
        register = inst.insn.reg_name(register_type.reg)
        state = proj.factory.full_init_state(addr=self.addr + size, add_options=angr.options.unicorn)
        setattr(state.regs, register, state.solver.BVS('a', 64))
        self.value = getattr(state.regs, register)
        if self.value != proj.arch.bits:
            self.value = self.value.zero_extend(proj.arch.bits - self.value.length)
        state.inspect.b('instruction', when=angr.BP_AFTER, action=self.explore_compare)
        sim = proj.factory.simulation_manager(state)
        sim.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
        sim.explore(find=self.explore_compare, n=100)
        ret = len(sim.found) > 0
        if ret is True:
            print("Found dependency of the destination register on future compare")
            return
        else:
            state.inspect.b('call', when=angr.BP_AFTER, action=self.explore_call)
            sim = proj.factory.simulation_manager(state)
            sim.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
            sim.explore(find=self.explore_call, n=100)
            ret = len(sim.found) > 0
            if ret is True:
                print("Found a dependency on destination register on future call")
                return

        print("found no dependencies for the destination register at the given instruction")
        return

    def explore_compare(self, state):
        p = angr.Project(self.target, load_options={'auto_load_libs': False})
        b = state.block()
        for i in b.capstone.insns:
            if i.insn.address != state.addr:
                continue
            if i.insn.mnemonic not in ['cmp', 'test']:
                return False
            for x in i.insn.operands:
                if x.type == 1:
                    reg = getattr(state.regs, i.insn.reg_name(x.reg))
                    leaves = list(reg.recursive_leaf_asts)
                    for leaf in leaves:
                        if leaf.length < self.value.length:
                            leaf = leaf.zero_extend(p.arch.bits - leaf.length)
                        result = leaf == self.value
                        if result.is_true():
                            l.info("Found dependency")
                            return True
        return False

    def explore_call(self, state):
        p = angr.Project(self.target, load_options={'auto_load_libs': False})
        try:
            b = state.block()
        except angr.errors.SimEngineError:
            return False
        try:
            ins = b.capstone.insns[0]
        except IndexError:
            return False
        if ins.insn.mnemonic != 'call':
            return False
        for x in range(3):
            curr = state.stack_pop()
            if curr.symbolic is False:
                continue
            for leaf in list(curr.recursive_leaf_asts):
                if leaf.length < self.value.length:
                    leaf = leaf.zero_extend(p.arch.bits - leaf.length)
                try:
                    res = leaf == self.value
                except claripy.errors.ClaripyOperationError:
                    return False
                if res.is_true():
                    return True
        for x in range(2):
            curr = state.stack_pop()
            if curr.symbolic is False:
                continue
            for leaf in list(curr.recursive_leaf_asts):
                res = leaf == self.value
                if res.is_true():
                    l.info("found a function call with 2 arguments")
                    return True
        return False
