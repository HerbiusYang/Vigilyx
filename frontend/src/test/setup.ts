import '@testing-library/jest-dom'

function createStorageMock() {
  const store = new Map<string, string>()

  return {
    get length() {
      return store.size
    },
    clear() {
      store.clear()
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null
    },
    removeItem(key: string) {
      store.delete(key)
    },
    setItem(key: string, value: string) {
      store.set(key, String(value))
    },
  }
}

function installStorageMock(name: 'localStorage' | 'sessionStorage') {
  const current = globalThis[name]
  if (
    current &&
    typeof current.getItem === 'function' &&
    typeof current.setItem === 'function' &&
    typeof current.removeItem === 'function'
  ) {
    return
  }

  const mock = createStorageMock()
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: mock,
  })
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, name, {
      configurable: true,
      value: mock,
    })
  }
}

installStorageMock('localStorage')
installStorageMock('sessionStorage')
