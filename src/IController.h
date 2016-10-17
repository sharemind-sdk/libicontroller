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
#include <map>
#include <memory>
#include <sharemind/Exception.h>
#include <sharemind/MicrosecondTime.h>
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

    SHAREMIND_DEFINE_EXCEPTION(Exception, ServerException);

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ServerException,
            InvalidInstanceUuidException,
            "Server provided invalid instance UUID!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ServerException,
            InvalidServerUuidException,
            "Server provided invalid server UUID!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ServerException,
            InvalidProtocolVersionException,
            "Unsupported controller protocol version!");

    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            ServerException,
            ConnectionClosedException,
            "Connection closed!");

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

            inline Data(std::size_t const numWorkers)
                : m_numWorkers((assert(numWorkers > 0u), numWorkers))
                , m_exceptionTimes{new UsTime[numWorkers]}
                , m_exceptions{new std::exception_ptr[numWorkers]}
            {}

        /* Fields: */

            std::size_t const m_numWorkers;
            ScopedArrayPtr<const UsTime> const m_exceptionTimes;
            ScopedArrayPtr<const std::exception_ptr> const m_exceptions;
        };

    public: /* Methods: */

        WorkerException(std::size_t const numWorkers)
            : m_d(new Data((assert(numWorkers > 0u), numWorkers)))
        {}

        WorkerException(WorkerException &&) = default;
        WorkerException(const WorkerException &) = default;
        WorkerException & operator=(WorkerException &&) = default;
        WorkerException & operator=(const WorkerException &) = default;

        inline std::size_t numExceptions() const noexcept {
            std::size_t r = 0u;
            for (std::size_t i = 0u; i < m_d->m_numWorkers; i++)
                if (m_d->m_exceptions[i])
                    r++;
            return r;
        }

        inline std::size_t numWorkers() const noexcept
        { return m_d->m_numWorkers; }

        inline UsTime exceptionTime(std::size_t const i) const noexcept
        { return m_d->m_exceptionTimes[(assert(i < m_d->m_numWorkers), i)]; }

        inline const UsTime * exceptionTimes() const noexcept
        { return m_d->m_exceptionTimes; }

        inline const std::exception_ptr & nested_ptr(std::size_t const i)
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

    public: /* Methods: */

        Value() = delete;
        Value(std::string &&) = delete;
        Value(const std::string &) = delete;
        Value & operator=(std::string &&) = delete;
        Value & operator=(const std::string &) = delete;

        Value(std::string pd,
              std::string type,
              std::shared_ptr<void> data,
              std::size_t const size)
            : m_pdName(std::move(pd))
            , m_typeName(
                  std::move(
                      (assert(!type.empty() && "Value type cannot be empty!"),
                       type)))
            , m_data(std::move((assert(data || size == 0u), data)))
            , m_size(size)
        {}

        inline const std::string & pdName() const noexcept { return m_pdName; }

        inline const std::string & typeName() const noexcept
        { return m_typeName; }

        inline std::shared_ptr<void> const & data() const noexcept
        { return m_data; }

        inline std::size_t size() const noexcept { return m_size; }

        template <typename T>
        inline T getValueAssertCorrectSize() const noexcept {
            assert(m_size == sizeof(T) && "Value is not of same size!");
            return *static_cast<const T *>(m_data.get());
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
            const T * const begin = static_cast<const T *>(m_data.get());
            return std::vector<T>(begin, begin + (m_size / sizeof(T)));
        }

        template <typename T>
        inline std::vector<T> getVector() const {
            if (m_size % sizeof(T) != 0u)
                throw ElementSizeMismatchException();
            return getVectorAssertCorrectSize<T>();
        }

        inline std::string getString() const
        { return std::string(static_cast<const char *>(m_data.get()), m_size); }

        template <typename Container>
        inline void assignToAssertCorrectSize(Container & v) const {
            using T = typename Container::value_type;
            assert(m_size % sizeof(T) == 0u && "Element value size mismatch!");
            const T * const begin = static_cast<const T *>(m_data.get());
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

        std::string const m_pdName;     /**< \note Empty for public types */
        std::string const m_typeName;
        std::shared_ptr<void> const m_data;
        std::size_t const m_size;

    }; /* class Value */

    using ValueMap = std::map<std::string, std::shared_ptr<Value> >;

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
