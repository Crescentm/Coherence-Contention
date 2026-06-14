# Thesis Language Blacklist

This note records words and sentence patterns that should be avoided in the thesis body, especially in Chapter 4.

The goal is not to ban all abstraction, but to avoid wording that is:

- too empty to carry technical meaning
- too close to slide language or report language
- too easy to overstate a conclusion
- not directly tied to an observable result, mechanism, or metric

## Blacklist

| Blacklisted wording | Why to avoid it | Preferred replacement |
| --- | --- | --- |
| `空间异质性` | Too abstract; the reader does not immediately know what varies | `页内不同缓存行的信号强弱差异` |
| `分析顺序依次为` | Sounds like presentation narration instead of thesis prose | Directly state the order, e.g. `本节先讨论...，再讨论...` |
| `鲁棒性` | Often too broad unless defined by a metric | Replace with the concrete effect, e.g. `在噪声下的变化情况` |
| `敏感性` | Too generic without a measured object | Replace with `变化幅度`, `变化差别`, `受影响程度` |
| `协同效应` | Often implies a strong causal conclusion | Replace with `叠加关系`, `共同作用`, `同时出现时的变化` |
| `机制可观测性` | Abstract and nominalized | Replace with `是否形成可观测时延差异` |
| `统计性质` | Too broad in result sections | Replace with `延迟分布`, `均值与方差`, `尾部比例`, `ROC`, `容量估计` |
| `可解释粒度` | Not concrete enough | Replace with `在多大范围内能够稳定区分` |
| `有效分区尺度` | Too conceptual for正文 | Replace with `实际分组方式`, `页内哪些位置会一起变化` |
| `量化链条` | Presentation-style wording | Replace with a direct sentence describing the analysis path |
| `时间域扰动` | Can sound abstract if not grounded | Replace with `时间上的干扰`, `调度和同步带来的变化` |
| `空间域扰动` | Can sound abstract if not grounded | Replace with `地址映射变化`, `页内位置变化` |
| `重塑` | Empty metaphor in technical writing | Replace with `改变`, `增加`, `降低`, `扩大`, `压缩` |
| `稳定结构` | Does not specify what is stable | Replace with `重复出现的块状分布`, `重复出现的条带` |
| `分区行为` | Vague without a concrete object | Replace with `哪些缓存行会落到同一组`, `矩阵中的分块现象` |
| `组织方式` | Too generic | Replace with `分组方式`, `地址映射方式` |
| `空间拓扑` | Too abstract for this thesis context | Replace with `空间分布`, `页内分布`, `地址映射关系` |
| `结构性噪声` | Too broad unless separately defined | Replace with `由调度和地址映射带来的波动` |
| `相位关系` | Too abstract in this context | Replace with `时间对齐关系`, `访问时刻的相对位置` |

## Sentence Patterns To Avoid

| Pattern | Why to avoid it | Preferred replacement |
| --- | --- | --- |
| `如果仅看...，容易误以为...` | First creates a false reading, then corrects it | Directly state the measured result and its interpretation |
| `该实验并不...，而是...` | Negative lead-in slows the argument | State the actual purpose directly |
| `从写作逻辑上看` | Meta-writing, not thesis content | Delete it |
| `这一观察对实验写作很重要` | Meta-writing, not thesis content | Replace with the actual consequence in the argument |
| `换言之` | Often introduces repetition rather than analysis | Delete it or replace with a direct statement |
| `核心思路是` | Presentation-style phrasing | State the method directly |
| `旨在` | Often sounds inflated | Use `用于`, `用来`, or state the action directly |
| `这意味着` | Often replaces concrete explanation | State the concrete implication directly |
| `最有效的粒度` | Over-strong unless benchmarked across all choices | Use `更接近该平台上的实际分组方式` or state the measured result directly |
| `完全命中` | Too absolute in narrative prose | Use the concrete metric, e.g. `定位准确率为 1.000000` |

## Writing Rule

When drafting a paragraph in the thesis body, prefer the following order:

1. State the observed quantity or phenomenon.
2. State the measured result.
3. State the interpretation that is directly supported by the result.

Avoid starting with:

- a rhetorical setup
- a presentation cue
- a meta-writing cue
- an abstract noun without a measurable referent

## Quick Check

Before finalizing a section, scan for the following signals:

- A noun that could be replaced by a metric or a visible phenomenon
- A sentence that starts by denying a wrong interpretation
- A sentence that talks about writing, structure, or presentation rather than the result
- A conclusion stronger than the data that precedes it

If one of these appears, rewrite the sentence in terms of:

- cycles
- mean / median / standard deviation
- tail proportion
- page / line / matrix / block
- address mapping
- timing alignment
