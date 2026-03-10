package langgraph

import (
	"context"
	"fmt"
)

const END = "__END__"

type StateGraph[T any] struct {
	nodes            map[string]NodeFunc[T]
	edges            map[string]string
	conditionalEdges map[string]ConditionalEdgeFunc[T]
	entryPoint       string
}

type NodeFunc[T any] func(ctx context.Context, state T) (T, error)
type ConditionalEdgeFunc[T any] func(ctx context.Context, state T) string

func NewStateGraph[T any]() *StateGraph[T] {
	return &StateGraph[T]{
		nodes:            make(map[string]NodeFunc[T]),
		edges:            make(map[string]string),
		conditionalEdges: make(map[string]ConditionalEdgeFunc[T]),
	}
}

func (g *StateGraph[T]) AddNode(name string, fn NodeFunc[T]) {
	g.nodes[name] = fn
}

func (g *StateGraph[T]) AddEdge(from, to string) {
	g.edges[from] = to
}

func (g *StateGraph[T]) AddConditionalEdges(from string, condition func(ctx context.Context, state T) string, routeMap map[string]string) {
	g.conditionalEdges[from] = func(ctx context.Context, state T) string {
		result := condition(ctx, state)
		if next, ok := routeMap[result]; ok {
			return next
		}
		return END
	}
}

func (g *StateGraph[T]) SetEntryPoint(name string) {
	g.entryPoint = name
}

func (g *StateGraph[T]) Compile() *Runnable[T] {
	return &Runnable[T]{graph: g}
}

type Runnable[T any] struct {
	graph *StateGraph[T]
}

func (r *Runnable[T]) Invoke(ctx context.Context, initialState T) (T, error) {
	state := initialState
	current := r.graph.entryPoint

	for current != END {
		node, ok := r.graph.nodes[current]
		if !ok {
			return state, fmt.Errorf("node not found: %s", current)
		}

		var err error
		state, err = node(ctx, state)
		if err != nil {
			return state, err
		}

		if next, ok := r.graph.edges[current]; ok {
			current = next
		} else if cond, ok := r.graph.conditionalEdges[current]; ok {
			current = cond(ctx, state)
		} else {
			current = END
		}
	}
	return state, nil
}
