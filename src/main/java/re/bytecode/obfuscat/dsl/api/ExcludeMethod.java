package re.bytecode.obfuscat.dsl.api;

import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * This @interface is used to exclude a method from being seen from the dsl parser
 */
@Target({ElementType.METHOD})
public @interface ExcludeMethod {

}