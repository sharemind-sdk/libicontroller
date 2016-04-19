/*
 * Copyright (C) 2015 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#ifndef SHAREMINDCONTROLLER_ICONTROLLER_H
#define SHAREMINDCONTROLLER_ICONTROLLER_H

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <sharemind/Exception.h>
#include <sharemind/MicrosecondTime.h>
#include <sharemind/ScopedObjectMap.h>
#include <string>
#include <utility>
#include <vector>


namespace sharemind {

/*
 * The correctly sized public data types for passing
 * the bytecode arguments and parsing the published results.
 */

using Bool = uint8_t;
using Int8 = int8_t;
using Int16 = int16_t;
using Int32 = int32_t;
using Int64 = int64_t;
using UInt8 = uint8_t;
using UInt16 = uint16_t;
using UInt32 = uint32_t;
using UInt64 = uint64_t;
using Float32 = float;
static_assert(sizeof(Float32) == 4u, "Float32 is not 32 bits wide!");
using Float64 = double;
static_assert(sizeof(Float64) == 8u, "Float64 is not 64-bits wide!");

class IController {

public: /* Types */

    SHAREMIND_DEFINE_EXCEPTION(std::exception, Exception);

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         NotReadyException,
                                         "Controller is not ready!");

    SHAREMIND_DEFINE_EXCEPTION(Exception, ArgumentException);

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(ArgumentException,
                                         TooManyArgumentsException,
                                         "Too many input arguments!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(ArgumentException,
                                         ArgumentTooBigException,
                                         "Argument too big!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ArgumentException,
            InvalidProtectionDomainException,
            "No protection domain of the given name found!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ArgumentException,
            InvalidDataTypeException,
            "No data type of the given name found!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ArgumentException,
            IncompatibleArgumentException,
            "The given argument is not compatible with the given data type!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ArgumentException,
            ClassifyException,
            "Failed to classify argument!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         IllegalBytecodeFilenameException,
                                         "Illegal bytecode filename!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         IllegalLocalFilenameException,
                                         "Illegal local filename!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         LocalFileOpenException,
                                         "Failed to open local file!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         LocalFileReadException,
                                         "Failed to read local file!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         LocalBytecodeEmptyException,
                                         "Local bytecode file was empty!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         LocalBytecodeTooBigException,
                                         "Local bytecode file was too big!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            DifferentResultSetSizesException,
            "Nodes published result sets of different size!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            DifferentResultSetsException,
            "Nodes published different result sets!");

    class WorkerException: public Exception {

    private: /* Types: */

        struct Data {

            template <typename T>
            struct ScopedArrayPtr {
                inline ~ScopedArrayPtr() noexcept { delete[] m_ptr; }
                operator T * () const { return m_ptr; }
                T * const m_ptr;
            };

        /* Methods: */

            inline Data(const size_t numWorkers)
                : m_numWorkers((assert(numWorkers > 0u), numWorkers))
                , m_exceptionTimes{new UsTime[numWorkers]}
                , m_exceptions{new std::exception_ptr[numWorkers]}
            {}

        /* Fields: */

            const size_t m_numWorkers;
            const ScopedArrayPtr<const UsTime> m_exceptionTimes;
            const ScopedArrayPtr<const std::exception_ptr> m_exceptions;
        };

    public: /* Methods: */

        WorkerException(const size_t numWorkers)
            : m_d(new Data((assert(numWorkers > 0u), numWorkers)))
        {}

        WorkerException(WorkerException &&) = default;
        WorkerException(const WorkerException &) = default;
        WorkerException & operator=(WorkerException &&) = default;
        WorkerException & operator=(const WorkerException &) = default;

        inline size_t numExceptions() const noexcept {
            size_t r = 0u;
            for (size_t i = 0u; i < m_d->m_numWorkers; i++)
                if (m_d->m_exceptions[i])
                    r++;
            return r;
        }

        inline size_t numWorkers() const noexcept { return m_d->m_numWorkers; }

        inline UsTime exceptionTime(const size_t i) const noexcept
        { return m_d->m_exceptionTimes[(assert(i < m_d->m_numWorkers), i)]; }

        inline const UsTime * exceptionTimes() const noexcept
        { return m_d->m_exceptionTimes; }

        inline const std::exception_ptr & nested_ptr(const size_t i)
                const noexcept
        { return m_d->m_exceptions[(assert(i < m_d->m_numWorkers), i)]; }

        inline const std::exception_ptr * nested_ptrs() const noexcept
        { return m_d->m_exceptions; }

        inline const char * what() const noexcept final override {
            return (m_d->m_numWorkers > 1u)
                   ? "Multiple worker exceptions caught!"
                   : "Worker exception caught!";
        }

    private: /* Fields: */

        const std::shared_ptr<Data> m_d;

    }; /* class WorkerException { */

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            RunKeepaliveTimeoutException,
            "No keepalive received within timeout while running code!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            UploadTimeoutException,
            "Timeout uploading!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         InvalidMessageException,
                                         "Received invalid message!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         RemoteError,
                                         "Remote end signalled an error!");

    SHAREMIND_DEFINE_EXCEPTION(Exception, ResultException);

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            SameNameResultException,
            "Result with the same name already received!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(ResultException,
                                         PublicResultTypeException,
                                         "A public result is of unknown type!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            InvalidPdResultException,
            "Invalid protection domain of result!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            PrivateResultTypeException,
            "A private result is of unknown type!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            PrivateResultFromWrongNodeException,
            "A private result was received from the wrong node!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            PrivateResultsDifferentSizeException,
            "The results published were of different size!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            PrivateResultInvalidSizeException,
            "The result published was of an invalid size!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            PublicResultMismatchException,
            "The public results of different nodes do not match!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ResultException,
            DeclassifyException,
            "Failed to declassify result!");

    class Value {

    public: /* Types: */

        SHAREMIND_DEFINE_EXCEPTION(IController::Exception, Exception);
        SHAREMIND_DEFINE_EXCEPTION(Exception, ParseException);
        SHAREMIND_DEFINE_EXCEPTION(ParseException, SizeMismatchException);
        SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(SizeMismatchException,
                                             DataSizeMismatchException,
                                             "Value is not of same size!");
        SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(SizeMismatchException,
                                             ElementSizeMismatchException,
                                             "Element value size mismatch!");

        enum CopyT { COPY };
        enum TakeOwnershipT { TAKE_OWNERSHIP };
        enum ReferenceT { REFERENCE };

    public: /* Methods: */

        Value() = delete;
        Value(std::string &&) = delete;
        Value(const std::string &) = delete;
        Value & operator=(std::string &&) = delete;
        Value & operator=(const std::string &) = delete;

        Value(const std::string & pd,
              const std::string & type,
              const void * const data,
              const size_t size,
              const CopyT)
            : m_pdName(
                  (assert(!type.empty() && "Value type cannot be empty!"),
                   assert((data || size == 0u)
                          && "Data pointer not given, but size was not zero!"),
                   pd))
            , m_typeName(type)
            , m_data((size == 0u) ? nullptr : ::operator new(size))
            , m_size(size)
            , m_ownData(size != 0u)
        {
            if (size != 0u)
                memcpy(const_cast<void *>(m_data), data, size);
        }

        Value(const std::string & pd,
              const std::string & type,
              const void * const data,
              const size_t size,
              const TakeOwnershipT)
            : m_pdName(
                  (assert(!type.empty() && "Value type cannot be empty!"),
                   assert((data || size == 0u)
                          && "Data pointer not given, but size was not zero!"),
                   pd))
            , m_typeName(type)
            , m_data(data)
            , m_size(size)
            , m_ownData(true)
        {}

        Value(const std::string & pd,
              const std::string & type,
              const void * const data,
              const size_t size,
              const ReferenceT)
            : m_pdName(
                  (assert(!type.empty() && "Value type cannot be empty!"),
                   assert((data || size == 0u)
                          && "Data pointer not given, but size was not zero!"),
                   pd))
            , m_typeName(type)
            , m_data(data)
            , m_size(size)
            , m_ownData(false)
        {}

        inline ~Value() noexcept {
            if (m_ownData)
                ::operator delete(const_cast<void *>(m_data));
        }

        inline const std::string & pdName() const noexcept { return m_pdName; }

        inline const std::string & typeName() const noexcept
        { return m_typeName; }

        inline const void * data() const noexcept { return m_data; }

        inline size_t size() const noexcept { return m_size; }

        template <typename T>
        inline T getValueAssertCorrectSize() const noexcept {
            assert(m_size == sizeof(T) && "Value is not of same size!");
            return *static_cast<const T *>(m_data);
        }

        template <typename T>
        inline T getValue() const {
            if (m_size != sizeof(T))
                throw DataSizeMismatchException();
            return getValueAssertCorrectSize<T>();
        }

        template <typename T>
        inline std::vector<T> getVectorAssertCorrectSize() const {
            assert(m_size % sizeof(T) == 0u && "Element value size mismatch!");
            const T * const begin = static_cast<const T *>(m_data);
            return std::vector<T>(begin, begin + (m_size / sizeof(T)));
        }

        template <typename T>
        inline std::vector<T> getVector() const {
            if (m_size % sizeof(T) != 0u)
                throw ElementSizeMismatchException();
            return getVectorAssertCorrectSize<T>();
        }

        inline std::string getString() const
        { return std::string(static_cast<const char *>(m_data), m_size); }

        template <typename Container>
        inline void assignToAssertCorrectSize(Container & v) const {
            using T = typename Container::value_type;
            assert(m_size % sizeof(T) == 0u && "Element value size mismatch!");
            const T * const begin = static_cast<const T *>(m_data);
            v.assign(begin, begin + (m_size / sizeof(T)));
        }

        template <typename Container>
        inline void assignTo(Container & v) const {
            using T = typename Container::value_type;
            if (m_size % sizeof(T) != 0u)
                throw ElementSizeMismatchException();
            assignToAssertCorrectSize(v);
        }

    protected: /* Fields: */

        const std::string m_pdName;     /**< \note Empty for public types */
        const std::string m_typeName;
        const void * const m_data;
        const size_t m_size;
        const bool m_ownData;

    }; /* class Value */

    using ValueMap = ScopedObjectMap<std::string, const Value>;

public: /* Methods */

    inline virtual ~IController() noexcept {}

    /**
     * Runs the requested bytecode on the application server nodes.
     * \param[in] codename The name of the bytecode file already uploaded to the
     *                     application server nodes.
     * \param[in] arguments The argument values to be passed to the bytecode.
     * \throws Exception on error.
     * \returns the results.
     */
    virtual ValueMap runCode(const std::string & codename,
                             const ValueMap & arguments) = 0;

#if 0
    /**
     * \brief Uploads the given bytecode file to the application server nodess.
     * \param[in] localfile The local bytecode file to upload.
     * \param[in] destfile The final name of the bytecode file on the
     *                     application server nodes.
     * \throws Exception on error.
     */
    virtual void uploadCode(const std::string & localfile,
                            const std::string & destfile) = 0;
#endif

    /**
     * \todo DEBUGGING CAPABILITIES:
     *       * startDebug
     *       * stopDebug
     *       * continue
     *       * step
     *       * set/clear breakpoints
     *       * memory/state inspection
     */

}; /* class IController */

} /* namespace sharemind { */

#endif /* SHAREMINDCONTROLLER_ICONTROLLER_H */
