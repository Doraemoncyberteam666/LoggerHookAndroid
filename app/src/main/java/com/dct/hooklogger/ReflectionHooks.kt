package com.dct.hooklogger

/**
 * Smali-friendly reflection helpers. These let a smali patch reach private APIs without
 * needing dex-time references (which can break across app updates). Every helper logs the
 * call so the round-trip is visible in `dct_hook.log`.
 */
internal object ReflectionHooks {
    fun invokeStatic(
        className: String?,
        methodName: String?,
        sig: Array<Class<*>>?,
        args: Array<Any?>?
    ): Any? {
        return HookRuntime.runCatchingForJni("invokeStatic($className.$methodName)") {
            val cls = Class.forName(className!!)
            val params = sig ?: emptyArray()
            val m = cls.getDeclaredMethod(methodName!!, *params)
            m.isAccessible = true
            m.invoke(null, *(args ?: emptyArray()))
        }
    }

    fun invokeVirtual(
        target: Any?,
        methodName: String?,
        sig: Array<Class<*>>?,
        args: Array<Any?>?
    ): Any? {
        return HookRuntime.runCatchingForJni("invokeVirtual(${target?.javaClass?.name}.$methodName)") {
            val cls = target?.javaClass ?: throw NullPointerException("target is null")
            val params = sig ?: emptyArray()
            val m = cls.getDeclaredMethod(methodName!!, *params)
            m.isAccessible = true
            m.invoke(target, *(args ?: emptyArray()))
        }
    }

    fun getField(target: Any?, fieldName: String?): Any? {
        return HookRuntime.runCatchingForJni("getField(${target?.javaClass?.name}.$fieldName)") {
            val cls = target?.javaClass ?: throw NullPointerException("target is null")
            val f = findField(cls, fieldName!!)
            f.isAccessible = true
            f.get(target)
        }
    }

    fun setField(target: Any?, fieldName: String?, value: Any?) {
        HookRuntime.runCatchingForJni("setField(${target?.javaClass?.name}.$fieldName)") {
            val cls = target?.javaClass ?: throw NullPointerException("target is null")
            val f = findField(cls, fieldName!!)
            f.isAccessible = true
            f.set(target, value)
        }
    }

    fun getStaticField(className: String?, fieldName: String?): Any? {
        return HookRuntime.runCatchingForJni("getStaticField($className.$fieldName)") {
            val cls = Class.forName(className!!)
            val f = findField(cls, fieldName!!)
            f.isAccessible = true
            f.get(null)
        }
    }

    fun setStaticField(className: String?, fieldName: String?, value: Any?) {
        HookRuntime.runCatchingForJni("setStaticField($className.$fieldName)") {
            val cls = Class.forName(className!!)
            val f = findField(cls, fieldName!!)
            f.isAccessible = true
            f.set(null, value)
        }
    }

    private fun findField(cls: Class<*>, name: String): java.lang.reflect.Field {
        var c: Class<*>? = cls
        while (c != null && c != Any::class.java) {
            try {
                return c.getDeclaredField(name)
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
        throw NoSuchFieldException("$name not found on ${cls.name}")
    }
}
