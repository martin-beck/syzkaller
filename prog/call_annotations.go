package prog

type ResTag int

const (
	NONETAG ResTag = iota
	ACCEPT
	BIND
	CONNECT
	LISTEN
)

type MarkerType int

const (
	NONEMARKER MarkerType = iota
	ENDEXCLUDE
	ENDINCLUDE
	STARTEXCLUDE
	STARTINCLUDE
)

type CallAnnotation struct {
	Tag     ResTag
	ResArg  *ResultArg
	callIdx int
	ResID   int64
}

type CallAnnotationMarker struct {
	Tag     ResTag
	SysName string
	Type    MarkerType
}

func (c *Call) HasResult(res *ResultArg) bool {
	hasRes := false
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		switch arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			if a == res {
				hasRes = true
			}
			if a.Res == res {
				hasRes = true
			}
			for use := range a.uses {
				if use == res {
					hasRes = true
				}
			}
		}
	})
	return hasRes
}

func (p *Prog) AnnotateResources(callIdx int) {
	var resTag ResTag
	var resArg *ResultArg
	var resID int64

	resTag = NONETAG
	resArg = nil
	resID = 0

	call := p.Calls[callIdx]

	switch call.Meta.Name {
	case "accept4":
		resArg = call.Ret.Res
		resTag = ACCEPT
	case "bind$inet", "bind$inet6":
		resArg = call.Args[0].(*ResultArg).Res
		resTag = BIND
	case "connect$inet", "connect$inet6":
		resArg = call.Args[0].(*ResultArg).Res
		resTag = CONNECT
	case "listen":
		resArg = call.Args[0].(*ResultArg).Res
		resTag = LISTEN
	}
	if resTag != NONETAG && resArg != nil {
		// if slices.Contains(annotations, resTag) {
		// 	panic("Call has resource with the same tag already.\n")
		// }
		p.Annotations = append(p.Annotations, CallAnnotation{resTag, resArg, callIdx, resID})
		// fmt.Fprintf(os.Stderr, "Annotating %s with tag %d\n", call.Meta.CallName, resTag)
	}
}

func (p *Prog) GetAnnotationIndicesMarker(caMarker CallAnnotationMarker) []int {
	var indices []int

	marker := caMarker.Type
	tag := caMarker.Tag
	syscallName := caMarker.SysName

	for _, an := range p.Annotations {
		inMarkerRange := false
		if marker == ENDINCLUDE || marker == ENDEXCLUDE || marker == NONEMARKER {
			inMarkerRange = true
		}
		if an.Tag == tag {
			resArg := an.ResArg
			if resArg == nil {
				panic("ResultArg of annotation is nil.\n")
			}
			for idx, call := range p.Calls {
				if call.HasResult(resArg) {
					// This call has the resource we are looking for

					if call.Meta.CallName == syscallName {
						// Got call that matches the marker syscall name
						// Preprocessing marker
						switch marker {
						case STARTINCLUDE:
							inMarkerRange = true
						case ENDEXCLUDE:
							inMarkerRange = false
						}
					}

					if inMarkerRange {
						// fmt.Fprintf(os.Stderr, "Found ResultArg on call:\n%#v\n", call)
						indices = append(indices, idx)
					}

					if call.Meta.CallName == syscallName {
						// Got call that matches the marker syscall name
						// Preprocessing marker
						switch marker {
						case STARTEXCLUDE:
							inMarkerRange = true
						case ENDINCLUDE:
							inMarkerRange = false
						}
					}
				}
			}
		}
	}

	return indices
}

func (p *Prog) GetAnnotationIndices(tag ResTag) []int {
	var indices []int

	for _, an := range p.Annotations {
		if an.Tag == tag {
			resArg := an.ResArg
			if resArg == nil {
				panic("ResultArg of annotation is nil.\n")
			}
			for idx, call := range p.Calls {
				if call.HasResult(resArg) {
					// fmt.Fprintf(os.Stderr, "Found ResultArg on call:\n%#v\n", call)
					indices = append(indices, idx)
				}
			}
		}
	}

	return indices
}
