import org.gradle.api.Project
import org.gradle.kotlin.dsl.getByType
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmCompilerOptions
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinNativeCompilerOptions

/**
 * Names the Kotlin module after the published artifact instead of the Gradle project, so the
 * `.kotlin_module` files under `META-INF` stay `<name>` and klib unique names stay
 * `<group>:<name>`, as Kotlin names them for a project called after the artifact.
 */
fun Project.kotlinModuleName(name: String) {
    val klibName = "$group:$name"
    extensions.getByType<KotlinMultiplatformExtension>().targets.configureEach {
        compilations.configureEach {
            if (compilationName == "main") {
                compileTaskProvider.configure {
                    when (val options = compilerOptions) {
                        is KotlinJvmCompilerOptions -> options.moduleName.set(name)
                        is KotlinNativeCompilerOptions -> options.moduleName.set(klibName)
                    }
                }
            }
        }
    }
}
