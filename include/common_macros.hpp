//
// Created by gzhuadmin on 23-5-13.
//

#ifndef LIVE_CAPTURE_COMMON_MACROS_HPP
#define LIVE_CAPTURE_COMMON_MACROS_HPP

#ifdef ENABLE_DEBUG
#define DEBUG_CALL(x)   x
#else
#define DEBUG_CALL(x)
#endif


#ifdef ENABLE_INFO
#define INFO_CALL(x)   x
#else
#define INFO_CALL(x)
#endif

#ifdef ENABLE_WARN
#define WARN_CALL(x)   x
#else
#define WARN_CALL(x)
#endif

#define RED(x) std::cout << "\n\33[31m=================" << x << "=================\033[0m\n\n"

#endif //LIVE_CAPTURE_COMMON_MACROS_HPP
